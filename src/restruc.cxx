#include "restruc.hxx"
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

Restruc::CFGraph::CFGraph()
    : entry_point(nullptr)
{
}

Restruc::CFGraph::CFGraph(Address entry_point)
    : entry_point(entry_point)
{
}

bool Restruc::CFGraph::is_complete() const
{
    return !instructions.empty() && unknown_jumps.empty() && has_ret
           || is_jump_table_entry();
}

bool Restruc::CFGraph::is_jump_table_entry() const
{
    if (instructions.size() != 1) {
        return false;
    }
    auto const &i = instructions.begin()->second;
    return i.mnemonic == ZYDIS_MNEMONIC_JMP;
}

Restruc::CFGraph::AnalysisResult Restruc::CFGraph::analyze(Address address)
{
    auto const &instruction = instructions[address];
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
        auto offset = instruction.operands[0].imm.value.s;
        Address dst = next_address + offset;
        auto type = get_jump_type(dst, address, next_address);
        add_jump(type, dst, address);
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

bool Restruc::CFGraph::is_conditional_jump(ZydisMnemonic mnemonic)
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

Restruc::CFGraph::SPManipulationType
Restruc::CFGraph::analyze_stack_pointer_manipulation(
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

void Restruc::CFGraph::add_instruction(
    Address address,
    ZydisDecodedInstruction const &instruction)
{
    instructions.emplace(address, instruction);
}

void Restruc::CFGraph::add_jump(Jump::Type type, Address dst, Address src)
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

void Restruc::CFGraph::add_call(Address dst, Address src, Address ret)
{
    calls.emplace(src, Call(dst, src, ret));
}

bool Restruc::CFGraph::promote_unknown_jump(Address dst, Jump::Type new_type)
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

void Restruc::CFGraph::visit(Address address)
{
    promote_unknown_jump(address, Jump::Inner);
}

Restruc::Jump::Type
Restruc::CFGraph::get_jump_type(Address dst, Address src, Address next) const
{
    // If jumping with offset 0, i.e. no jump
    if (dst == next) {
        return Jump::Inner;
    }
    // If jump is first cfgraph instruction
    if (instructions.size() == 1) {
        // Assume JMP table
        return Jump::Outer;
    }
    // If destination is one of the previous instructions
    if (instructions.contains(dst)) {
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

bool Restruc::CFGraph::stack_depth_is_ambiguous() const
{
    return stack_depth == -1;
}

bool Restruc::CFGraph::is_inside(Address address) const
{
    return instructions.contains(address) || inner_jumps.contains(address);
}

Restruc::Restruc(std::filesystem::path const &pe_path)
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

void Restruc::fill_cfgraph(CFGraph &cfgraph)
{
    Address address;
    Address next_address;
    if (cfgraph.instructions.empty()) {
        next_address = cfgraph.entry_point;
    }
    else {
        next_address = cfgraph.instructions.rbegin()->first;
    }
    Address end = pe_.get_end(next_address);
    while (true) {
        address = next_address;
        if (address == nullptr || address >= end) {
            break;
        }

        ZydisDecodedInstruction instruction;
        ZYAN_THROW(ZydisDecoderDecodeBuffer(&decoder_,
                                            address,
                                            end - address,
                                            &instruction));
#ifdef DEBUG_ANALYSIS
        dump_instruction(std::clog,
                         pe_.raw_to_virtual_address(address),
                         instruction);
#endif

        cfgraph.add_instruction(address, instruction);
        auto analysis_status = cfgraph.analyze(address);
        next_address = analysis_status.next_address;
    }
}

void Restruc::post_fill_cfgraph(CFGraph &cfgraph)
{
    // TODO
}

void Restruc::analyze_cfgraph(Address entry_point)
{
    ++analyzing_threads_count_;
    analyzing_threads_.emplace_back([&, entry_point] {
        try {
            ScopeGuard decrement_analyzing_threads_count([this]() noexcept {
                --analyzing_threads_count_;
                cfgraphs_cv_.notify_all();
            });

            {
                std::lock_guard<std::mutex> creating_cfgraph_guard(
                    creating_cfgraph_mutex_);
                // Prevent recursive analysis
                if (created_cfgraphs_.contains(entry_point)) {
                    return;
                }
                created_cfgraphs_.emplace(entry_point);
            }

            auto cfgraph = std::make_unique<CFGraph>(entry_point);
            fill_cfgraph(*cfgraph);

            {
                std::lock_guard<std::mutex> adding_cfgraph_guard(
                    cfgraphs_mutex_);
                cfgraphs_.emplace(entry_point, std::move(cfgraph));
                unanalyzed_cfgraphs_.push_back(entry_point);
            }
        }
        catch (zyan_error const &e) {
            std::cerr << std::hex << std::setfill('0')
                      << "Failed to analyze cfgraph " << std::setw(8)
                      << pe_.raw_to_virtual_address(entry_point) << ", error:\n"
                      << e.what() << '\n';
        }
    });
}

void Restruc::post_analyze_cfgraph(CFGraph &cfgraph)
{
    ++analyzing_threads_count_;
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

Address Restruc::pop_unanalyzed_cfgraph()
{
    std::lock_guard<std::mutex> popping_cfgraph_guard(cfgraphs_mutex_);
    auto address = unanalyzed_cfgraphs_.front();
    unanalyzed_cfgraphs_.pop_front();
    return address;
}

void Restruc::find_and_analyze_cfgraphs()
{
    analyze_cfgraph(pe_.get_entry_point());
    while (true) {
        if (unanalyzed_cfgraphs_.empty()
            || analyzing_threads_count_ >= max_analyzing_threads_) {
            // Wait for all analyzing threads
            cfgraphs_cv_.wait(std::unique_lock(cfgraphs_mutex_),
                              [this] { return analyzing_threads_count_ == 0; });
        }
        if (analyzing_threads_count_ == 0 && unanalyzed_cfgraphs_.empty()) {
            break;
        }

        auto &cfgraph = cfgraphs_[pop_unanalyzed_cfgraph()];

        // Iterate over unique call destinations
        for (auto it = cfgraph->calls.begin(), end = cfgraph->calls.end();
             it != end;
             it = cfgraph->calls.upper_bound(it->first)) {
            analyze_cfgraph(it->second.dst);
        }

        // Iterate over unique outer jumps
        for (auto it = cfgraph->outer_jumps.begin(),
                  end = cfgraph->outer_jumps.end();
             it != end;
             it = cfgraph->outer_jumps.upper_bound(it->first)) {
            analyze_cfgraph(it->second.dst);
        }
    }
    wait_for_all_analyzing_threads();
}

void Restruc::promote_jumps_to_outer()
{
    // Promote all unknown jumps to outer jumps
    // Because we have all functions, and assume that all
    // unknown jumps from other functions are "outer".
    for (auto const &[entry_point, cfgraph] : cfgraphs_) {
        bool needs_post_analysis = false;
        for (auto ijump = cfgraph->unknown_jumps.begin();
             ijump != cfgraph->unknown_jumps.end();) {
            if (cfgraphs_.contains(ijump->second.dst)) {
                cfgraph->add_jump(Jump::Outer,
                                  ijump->second.dst,
                                  ijump->second.src);
                ijump = cfgraph->unknown_jumps.erase(ijump);
                needs_post_analysis = true;
            }
            else {
                ++ijump;
            }
        }
        if (needs_post_analysis) {
            unanalyzed_cfgraphs_.push_back(entry_point);
        }
    }
}

void Restruc::promote_jumps_to_inner()
{
    // Promote all unknown jumps to inner jumps,
    // as some unknown jumps were promoted to outer jumps,
    // the remaining jumps should be inner jumps.
    for (auto const &[entry_point, cfgraph] : cfgraphs_) {
        while (!cfgraph->unknown_jumps.empty()) {
            auto ijump = cfgraph->unknown_jumps.begin();
            cfgraph->add_jump(Jump::Inner,
                              ijump->second.dst,
                              ijump->second.src);
            cfgraph->unknown_jumps.erase(ijump);
        }
    }
}

void Restruc::post_analyze_cfgraphs()
{
    while (!unanalyzed_cfgraphs_.empty()) {
        if (analyzing_threads_count_ >= max_analyzing_threads_) {
            // Wait for all analyzing threads
            cfgraphs_cv_.wait(std::unique_lock(cfgraphs_mutex_), [this] {
                return analyzing_threads_count_ < max_analyzing_threads_;
            });
        }
        auto &cfgraph = cfgraphs_[pop_unanalyzed_cfgraph()];
        post_analyze_cfgraph(*cfgraph);
    }
    wait_for_all_analyzing_threads();
}

void Restruc::analyze()
{
    find_and_analyze_cfgraphs();
    promote_jumps_to_outer();
    promote_jumps_to_inner();
    post_analyze_cfgraphs();
}

void Restruc::wait_for_all_analyzing_threads()
{
    std::for_each(std::execution::par_unseq,
                  analyzing_threads_.begin(),
                  analyzing_threads_.end(),
                  [](std::thread &t) { t.join(); });
    analyzing_threads_.clear();
}

void Restruc::set_max_analyzing_threads(size_t amount)
{
    max_analyzing_threads_ = amount;
}

#ifndef NDEBUG

void Restruc::debug(std::ostream &os)
{
    analyze();
    for (auto const &f : cfgraphs_) {
        dump_cfgraph(os, formatter_, *f.second);
    }
}

void Restruc::dump_instruction(std::ostream &os,
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

void Restruc::dump_cfgraph(std::ostream &os,
                           ZydisFormatter const &formatter,
                           CFGraph const &cfgraph)
{
    char buffer[256];
    os << std::hex << std::setfill('0');
    os << std::setw(8) << pe_.raw_to_virtual_address(cfgraph.entry_point)
       << ":\n";
    for (auto const &[address, instruction] : cfgraph.instructions) {
        auto va = pe_.raw_to_virtual_address(address);
        dump_instruction(os, va, instruction);
    }
    os << '\n';
}

#endif
