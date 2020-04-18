#include "reflo.hxx"
#include "scope_guard.hxx"
#include "zyan_error.hxx"

#include <cinttypes>
#include <cstdio>
#include <execution>
#include <functional>
#include <iomanip>
#include <iostream>
#include <string>

//#define DEBUG_ANALYSIS

using namespace rstc;

#define ZYAN_THROW(expr)               \
    do {                               \
        ZyanStatus _status = (expr);   \
        if (ZYAN_FAILED(_status)) {    \
            throw zyan_error(_status); \
        }                              \
    } while (0)

Reflo::CFGraph::CFGraph(Address entry_point, ContextPtr context)
    : entry_point(entry_point)
    , initial_context(std::move(context))
{
}

void Reflo::CFGraph::emulate(ZydisDecodedInstruction const &instruction,
                             Context &context) const
{
    // TODO: analyze context
}

Reflo::ContextPtr Reflo::CFGraph::get_context(Address address) const
{
    if (disassembly.empty()) {
        return std::move(initial_context);
    }
    auto it = disassembly.upper_bound(address);
    auto const &ctx_instr = it->second;
    auto context = std::make_unique<Context>(*ctx_instr.context);
    emulate(*ctx_instr.instruction, *context);
    return std::move(context);
}

Reflo::CFGraph::AnalysisResult Reflo::CFGraph::analyze(Address address,
                                                       Instruction instr)
{
    auto result = disassembly.emplace(
        address,
        ContextedInstruction{ std::move(instr), get_context(address) });
    auto const &instruction = *result.first->second.instruction;
    Address next_address = address + instruction.length;
    visit(address);
    if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL) {
        // Assume calls always return (i.e. they are not no-return)
        Address dst = next_address + instruction.operands[0].imm.value.s;
        add_call(dst, address, next_address);
    }
    else if (instruction.mnemonic == ZYDIS_MNEMONIC_RET) {
        has_ret = true;
        if (!is_inside(next_address)) {
            return { Complete, nullptr };
        }
    }
    else if (instruction.mnemonic == ZYDIS_MNEMONIC_JMP
             || is_conditional_jump(instruction.mnemonic)) {
        bool unconditional = instruction.mnemonic == ZYDIS_MNEMONIC_JMP;
        auto const &op = instruction.operands[0];
        Address dst = nullptr;
        Jump::Type type = Jump::Unknown;
        if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            dst = next_address + instruction.operands[0].imm.value.s;
            type = get_jump_type(dst, address, next_address);
            add_jump(type, dst, address);
        }
        else {
            return { UnknownJump, nullptr };
        }
        // TODO: Support more op.type-s.
        if (unconditional) {
            switch (type) {
            case Jump::Unknown:
                if (!promote_unknown_jump(next_address, Jump::Inner)) {
                    return { UnknownJump, nullptr };
                }
                break;
            case Jump::Inner:
                if (dst < next_address) {
                    // Looping inside CFGraph
                    return { InnerJump, nullptr };
                }
                break;
            case Jump::Outer:
                //
                return { OuterJump, nullptr };
            }
        }
    }
    else {
        auto sp_status = analyze_stack_pointer_manipulation(instruction);
        if (sp_status == SPModified) {
            stack_was_modified = true;
        }
    }
    return { Next, next_address };
}

bool Reflo::CFGraph::is_conditional_jump(ZydisMnemonic mnemonic)
{
    switch (mnemonic) {
    case ZYDIS_MNEMONIC_JB:
    case ZYDIS_MNEMONIC_JBE:
    case ZYDIS_MNEMONIC_JCXZ:
    case ZYDIS_MNEMONIC_JECXZ:
    case ZYDIS_MNEMONIC_JKNZD:
    case ZYDIS_MNEMONIC_JKZD:
    case ZYDIS_MNEMONIC_JL:
    case ZYDIS_MNEMONIC_JLE:
    case ZYDIS_MNEMONIC_JMP:
    case ZYDIS_MNEMONIC_JNB:
    case ZYDIS_MNEMONIC_JNBE:
    case ZYDIS_MNEMONIC_JNL:
    case ZYDIS_MNEMONIC_JNLE:
    case ZYDIS_MNEMONIC_JNO:
    case ZYDIS_MNEMONIC_JNP:
    case ZYDIS_MNEMONIC_JNS:
    case ZYDIS_MNEMONIC_JNZ:
    case ZYDIS_MNEMONIC_JO:
    case ZYDIS_MNEMONIC_JP:
    case ZYDIS_MNEMONIC_JRCXZ:
    case ZYDIS_MNEMONIC_JS:
    case ZYDIS_MNEMONIC_JZ:
        // Jxx
    case ZYDIS_MNEMONIC_LOOP:
    case ZYDIS_MNEMONIC_LOOPE:
    case ZYDIS_MNEMONIC_LOOPNE:
        // LOOPxx
        return true;
    }
    return false;
}

Reflo::CFGraph::SPManipulationType
Reflo::CFGraph::analyze_stack_pointer_manipulation(
    ZydisDecodedInstruction const &instruction)
{
    if (instruction.operand_count == 2) {
        auto const &dst = instruction.operands[0];
        auto const &src = instruction.operands[1];
        if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER
            && dst.reg.value == ZYDIS_REGISTER_RSP) {
            if (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                switch (instruction.mnemonic) {
                case ZYDIS_MNEMONIC_ADD:
                    stack_depth -= src.imm.value.s;
                    return SPModified;
                case ZYDIS_MNEMONIC_SUB:
                    stack_depth += src.imm.value.s;
                    return SPModified;
                default: stack_depth = -1; return SPAmbiguous;
                }
            }
            else {
                stack_depth = -1;
                return SPAmbiguous;
            }
        }
    }
    else {
        switch (instruction.mnemonic) {
        case ZYDIS_MNEMONIC_PUSH: stack_depth += 8; return SPModified;
        case ZYDIS_MNEMONIC_PUSHF: stack_depth += 2; return SPModified;
        case ZYDIS_MNEMONIC_PUSHFD: stack_depth += 4; return SPModified;
        case ZYDIS_MNEMONIC_PUSHFQ: stack_depth += 8; return SPModified;

        case ZYDIS_MNEMONIC_POP: stack_depth -= 8; return SPModified;
        case ZYDIS_MNEMONIC_POPF: stack_depth -= 2; return SPModified;
        case ZYDIS_MNEMONIC_POPFD: stack_depth -= 4; return SPModified;
        case ZYDIS_MNEMONIC_POPFQ: stack_depth -= 8; return SPModified;
        }
    }
    return SPUnmodified;
}

Address Reflo::CFGraph::get_unanalized_inner_jump_dst() const
{
    for (auto it = inner_jumps.begin(), end = inner_jumps.end(); it != end;
         it = inner_jumps.upper_bound(it->first)) {
        if (!disassembly.contains(it->first)) {
            return it->first;
        }
    }
    return nullptr;
}

void Reflo::CFGraph::add_jump(Jump::Type type, Address dst, Address src)
{
    switch (type) {
    case Jump::Inner:
        inner_jumps.emplace(dst, Jump(Jump::Inner, dst, src));
        break;
    case Jump::Outer:
        outer_jumps.emplace(dst, Jump(Jump::Outer, dst, src));
        break;
    case Jump::Unknown:
        unknown_jumps.emplace(dst, Jump(Jump::Unknown, dst, src));
        break;
    }
}

void Reflo::CFGraph::add_call(Address dst, Address src, Address ret)
{
    calls.emplace(src, Call(dst, src, ret));
}

bool Reflo::CFGraph::promote_unknown_jump(Address dst, Jump::Type new_type)
{
    bool promoted = false;
    while (true) {
        if (auto jump = unknown_jumps.extract(dst); !jump.empty()) {
            promoted = true;
            add_jump(new_type, dst, jump.mapped().src);
        }
        else {
            break;
        }
    }
    return promoted;
}

void Reflo::CFGraph::visit(Address address)
{
    promote_unknown_jump(address, Jump::Inner);
}

Reflo::Jump::Type
Reflo::CFGraph::get_jump_type(Address dst, Address src, Address next) const
{
    // If jumping with offset 0, i.e. no jump
    if (dst == next) {
        return Jump::Inner;
    }
    // If jump is first cfgraph instruction
    if (disassembly.size() == 1) {
        // Assume JMP table
        return Jump::Outer;
    }
    // If destination is one of the previous instructions
    if (disassembly.contains(dst)) {
        return Jump::Inner;
    }
    // If jumping above entry-point
    if (dst < entry_point) {
        // Assume no inner jumps are made above entry-point
        return Jump::Outer;
    }
    if (!stack_depth_is_ambiguous()) {
        if (stack_depth != 0) {
            // Assume no outer jumps are made with dirty stack
            return Jump::Inner;
        }
        else {
            // If stack depth was modified previously, and returned to 0
            // Assume outer jump (optimized tail call).
            if (stack_was_modified) {
                return Jump::Outer;
            }
        }
    }
    return Jump::Unknown;
}

bool Reflo::CFGraph::stack_depth_is_ambiguous() const
{
    return stack_depth == -1;
}

bool Reflo::CFGraph::is_inside(Address address) const
{
    return disassembly.contains(address) || inner_jumps.contains(address);
}

Reflo::Reflo(std::filesystem::path const &pe_path)
    : pe_(pe_path)
    , max_analyzing_threads_(std::thread::hardware_concurrency())
{
    ZYAN_THROW(ZydisDecoderInit(&decoder_,
                                ZYDIS_MACHINE_MODE_LONG_64,
                                ZYDIS_ADDRESS_WIDTH_64));
#ifndef NDEBUG
    ZYAN_THROW(ZydisFormatterInit(&formatter_, ZYDIS_FORMATTER_STYLE_INTEL));
#endif
}

Instruction Reflo::decode_instruction(Address address, Address end)
{
    Instruction instruction = std::make_unique<ZydisDecodedInstruction>();
    ZYAN_THROW(ZydisDecoderDecodeBuffer(&decoder_,
                                        address,
                                        end - address,
                                        instruction.get()));
    return std::move(instruction);
}

void Reflo::fill_cfgraph(CFGraph &cfgraph)
{
    Address address;
    Address next_address;
    if (cfgraph.disassembly.empty()) {
        next_address = cfgraph.entry_point;
    }
    else {
        next_address = cfgraph.disassembly.rbegin()->first;
    }
    Address end = pe_.get_end(next_address);
    while (true) {
        address = next_address;
        if (address == nullptr || address >= end) {
            break;
        }
        auto instruction = decode_instruction(address, end);
#ifdef DEBUG_ANALYSIS
        dump_instruction(std::clog,
                         pe_.raw_to_virtual_address(address),
                         instruction);
#endif
        auto analysis_status = cfgraph.analyze(address, std::move(instruction));
        next_address = analysis_status.next_address;
    }
}

void Reflo::post_fill_cfgraph(CFGraph &cfgraph)
{
    while (auto address = cfgraph.get_unanalized_inner_jump_dst()) {
        auto next_address = address;
        auto end = pe_.get_end(address);
        while (true) {
            address = next_address;
            if (address == nullptr || address >= end) {
                break;
            }
            auto instruction = decode_instruction(address, end);
#ifdef DEBUG_ANALYSIS
            dump_instruction(std::clog,
                             pe_.raw_to_virtual_address(address),
                             instruction);
#endif
            auto analysis_status =
                cfgraph.analyze(address, std::move(instruction));
            next_address = analysis_status.next_address;
        }
    }
}

void Reflo::wait_before_analysis_run()
{
    cfgraphs_cv_.wait(std::unique_lock(cfgraphs_mutex_), [this] {
        return analyzing_threads_count_ < max_analyzing_threads_;
    });
    ++analyzing_threads_count_;
}

void Reflo::run_cfgraph_analysis(Address entry_point, ContextPtr context)
{
    // Prevent recursive analysis
    if (created_cfgraphs_.contains(entry_point)) {
        return;
    }
    created_cfgraphs_.emplace(entry_point);
    wait_before_analysis_run();
    analyzing_threads_.emplace_back(
        [this, entry_point, context = std::move(context)]() mutable {
            try {
                ScopeGuard decrement_analyzing_threads_count([this]() noexcept {
                    --analyzing_threads_count_;
                    cfgraphs_cv_.notify_all();
                });

#ifdef DEBUG_ANALYSIS
                std::clog << "Analyzing: " << std::hex << std::setfill('0')
                          << std::setw(8)
                          << pe_.raw_to_virtual_address(entry_point) << '\n';
#endif

                auto cfgraph =
                    std::make_unique<CFGraph>(entry_point, std::move(context));
                fill_cfgraph(*cfgraph);

                {
                    std::lock_guard<std::mutex> adding_cfgraph_guard(
                        cfgraphs_mutex_);
                    cfgraphs_.emplace(entry_point, std::move(cfgraph));
                    unprocessed_cfgraphs_.push_back(entry_point);
                }
            }
            catch (zyan_error const &e) {
                std::cerr << std::hex << std::setfill('0')
                          << "Failed to analyze cfgraph " << std::setw(8)
                          << pe_.raw_to_virtual_address(entry_point)
                          << ", error:\n"
                          << e.what() << '\n';
            }
        });
}

void Reflo::run_cfgraph_post_analysis(CFGraph &cfgraph)
{
    wait_before_analysis_run();
    analyzing_threads_.emplace_back([&] {
        try {
            ScopeGuard decrement_analyzing_threads_count([this]() noexcept {
                --analyzing_threads_count_;
                cfgraphs_cv_.notify_all();
            });
            post_fill_cfgraph(cfgraph);
        }
        catch (zyan_error const &e) {
            std::cerr << std::hex << std::setfill('0')
                      << "Failed to post analyze cfgraph " << std::setw(8)
                      << pe_.raw_to_virtual_address(cfgraph.entry_point)
                      << ", error:\n"
                      << e.what() << '\n';
        }
    });
}

Address Reflo::pop_unprocessed_cfgraph()
{
    std::lock_guard<std::mutex> popping_cfgraph_guard(cfgraphs_mutex_);
    auto address = unprocessed_cfgraphs_.front();
    unprocessed_cfgraphs_.pop_front();
    return address;
}

void Reflo::find_and_analyze_cfgraphs()
{
    run_cfgraph_analysis(pe_.get_entry_point(),
                         std::move(make_initial_context()));
    while (true) {
        if (unprocessed_cfgraphs_.empty()) {
            // Wait for all analyzing threads
            cfgraphs_cv_.wait(std::unique_lock(cfgraphs_mutex_),
                              [this] { return analyzing_threads_count_ == 0; });
        }
        if (analyzing_threads_count_ == 0 && unprocessed_cfgraphs_.empty()) {
            break;
        }

        auto &cfgraph = cfgraphs_[pop_unprocessed_cfgraph()];

        // Iterate over unique call destinations
        for (auto it = cfgraph->calls.begin(), end = cfgraph->calls.end();
             it != end;
             it = cfgraph->calls.upper_bound(it->first)) {
            auto const &jump = it->second;
            run_cfgraph_analysis(jump.dst,
                                 std::move(make_cfgraph_initial_context(
                                     *cfgraph->disassembly[jump.src].context)));
        }

        // Iterate over unique outer jumps
        for (auto it = cfgraph->outer_jumps.begin(),
                  end = cfgraph->outer_jumps.end();
             it != end;
             it = cfgraph->outer_jumps.upper_bound(it->first)) {
            auto const &jump = it->second;
            run_cfgraph_analysis(jump.dst,
                                 std::move(make_cfgraph_initial_context(
                                     *cfgraph->disassembly[jump.src].context)));
        }
    }
    wait_for_analysis();
}

void Reflo::promote_jumps_to_outer()
{
    // Promote all unknown jumps to outer jumps
    // Because we have all cfgraphs, and we can assume that all
    // unknown jumps from a cfgraphs is "outer"
    // if dst is in list of existing cfgraphs_.
    for (auto const &[entry_point, cfgraph] : cfgraphs_) {
        for (auto ijump = cfgraph->unknown_jumps.begin();
             ijump != cfgraph->unknown_jumps.end();) {
            if (cfgraphs_.contains(ijump->second.dst)) {
                cfgraph->add_jump(Jump::Outer,
                                  ijump->second.dst,
                                  ijump->second.src);
                ijump = cfgraph->unknown_jumps.erase(ijump);
            }
            else {
                ++ijump;
            }
        }
    }
}

void Reflo::promote_jumps_to_inner()
{
    // Promote all unknown jumps to inner jumps,
    // as some unknown jumps were promoted to outer jumps,
    // the remaining jumps should be inner jumps.
    for (auto const &[entry_point, cfgraph] : cfgraphs_) {
        bool needs_post_analysis = !cfgraph->unknown_jumps.empty();
        while (!cfgraph->unknown_jumps.empty()) {
            auto ijump = cfgraph->unknown_jumps.begin();
            cfgraph->add_jump(Jump::Inner,
                              ijump->second.dst,
                              ijump->second.src);
            cfgraph->unknown_jumps.erase(ijump);
        }
        if (needs_post_analysis) {
            unprocessed_cfgraphs_.push_back(entry_point);
        }
    }
}

void Reflo::post_analyze_cfgraphs()
{
    while (!unprocessed_cfgraphs_.empty()) {
        auto &cfgraph = cfgraphs_[pop_unprocessed_cfgraph()];
        run_cfgraph_post_analysis(*cfgraph);
    }
    wait_for_analysis();
}

void Reflo::analyze()
{
    find_and_analyze_cfgraphs();
    while (unknown_jumps_exist()) {
        promote_jumps_to_outer();
        // Tehnically, we can't promote unknown jumps to inner jumps, as
        // we still haven't explored the program as a whole, and some cfgraphs
        // (functions) might be unlisted yet.
        promote_jumps_to_inner();
        post_analyze_cfgraphs();
    }
}

void Reflo::wait_for_analysis()
{
    std::for_each(analyzing_threads_.begin(),
                  analyzing_threads_.end(),
                  [](std::thread &t) { t.join(); });
    analyzing_threads_.clear();
}

bool Reflo::unknown_jumps_exist() const
{
    return std::any_of(cfgraphs_.cbegin(),
                       cfgraphs_.cend(),
                       [this](auto const &cfgraph) {
                           return !cfgraph.second->unknown_jumps.empty();
                       });
}

void Reflo::set_max_analyzing_threads(size_t amount)
{
    max_analyzing_threads_ = amount;
}

std::unique_ptr<Reflo::Context> Reflo::make_initial_context()
{
    auto c = std::make_unique<Context>();
    c->rax = pe_.raw_to_virtual_address(pe_.get_entry_point());
    c->rbx = 0;
    c->rcx.unset(); // &PEB
    c->rdx = c->rax;
    c->rbp = 0;
    c->rsp = 0;
    c->rsi = 0;
    c->rdi = 0;
    c->r8 = c->rcx;
    c->r9 = c->rax;
    c->r10 = 0;
    c->r11 = 0;
    c->r12 = 0;
    c->r13 = 0;
    c->r14 = 0;
    c->r15 = 0;
    c->rflags = 0x244;
    return std::move(c);
}

std::unique_ptr<Reflo::Context>
Reflo::make_cfgraph_initial_context(Context const &src_context)
{
    auto c = std::make_unique<Context>(src_context);
    c->rsp -= 8; // size of address
    return std::move(c);
}

#ifndef NDEBUG

void Reflo::debug(std::ostream &os)
{
    analyze();
    for (auto const &f : cfgraphs_) {
        dump_cfgraph(os, formatter_, *f.second);
    }
}

void Reflo::dump_instruction(std::ostream &os,
                             DWORD va,
                             ZydisDecodedInstruction const &instruction)
{
    char buffer[256];
    ZYAN_THROW(ZydisFormatterFormatInstruction(&formatter_,
                                               &instruction,
                                               buffer,
                                               sizeof(buffer),
                                               va));
    os << std::hex << std::setfill('0') << std::setw(8) << va << "    "
       << buffer << '\n';
}

void Reflo::dump_cfgraph(std::ostream &os,
                         ZydisFormatter const &formatter,
                         CFGraph const &cfgraph)
{
    char buffer[256];
    os << std::hex << std::setfill('0');
    os << std::setw(8) << pe_.raw_to_virtual_address(cfgraph.entry_point)
       << ":\n";
    for (auto const &[address, contexted_instruction] : cfgraph.disassembly) {
        auto va = pe_.raw_to_virtual_address(address);
        dump_instruction(os, va, *contexted_instruction.instruction);
    }
    os << '\n';
}

#endif
