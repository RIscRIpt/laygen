#include "restruc.hxx"

#include "zyan_error.hxx"

#include <cinttypes>
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <string>

using namespace rstc;

#define ZYAN_THROW(expr)               \
    do {                               \
        ZyanStatus _status = (expr);   \
        if (ZYAN_FAILED(_status)) {    \
            throw zyan_error(_status); \
        }                              \
    } while (0)

void Restruc::PotentialSubCFGraphs::add(std::unique_ptr<CFGraph> &&sub_cfgraph)
{
    // TODO
}

std::vector<std::unique_ptr<Restruc::CFGraph>>
Restruc::PotentialSubCFGraphs::extract(Address dst)
{
    // TODO
    return {};
}

Restruc::CFGraph::CFGraph()
    : entry_point(nullptr)
    , outer_cfgraph(nullptr)
{
}

Restruc::CFGraph::CFGraph(Address entry_point, CFGraph *outer_cfgraph)
    : entry_point(entry_point)
    , outer_cfgraph(outer_cfgraph)
{
}

bool Restruc::CFGraph::is_complete() const
{
    return !instructions.empty() && unknown_jumps.empty() && has_ret;
}

bool Restruc::CFGraph::can_merge_with_outer_cfgraph() const
{
    if (!outer_cfgraph) {
        return false;
    }
    if (is_complete()) {
        return true;
    }
    if (instructions.empty()) {
        return false;
    }
    auto const &last_outer_instruction = *outer_cfgraph->instructions.rbegin();
    auto const &first_instruction = *instructions.begin();
    // Can merge if first instruction of this CFGraph is comes right
    // after the last instruction of outer CFGraph.
    return first_instruction.first
           == last_outer_instruction.first
                  + last_outer_instruction.second.length;
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

bool Restruc::CFGraph::promote_outer_unknown_jump(Address dst,
                                                  Jump::Type new_type)
{
    if (!outer_cfgraph) {
        return false;
    }
    return outer_cfgraph->promote_unknown_jump(dst, new_type);
}

void Restruc::CFGraph::visit(Address address)
{
    promote_unknown_jump(address, Jump::Inner);
    promote_outer_unknown_jump(address, Jump::Inner);
}

Restruc::Jump::Type
Restruc::CFGraph::get_jump_type(Address dst, Address src, Address next) const
{
    // If jumping with offset 0, i.e. no jump
    if (dst == next) {
        return Jump::Inner;
    }
    // If jump is first function instruction
    if (instructions.size() == 1) {
        // Assume JMP table
        return Jump::Outer;
    }
    // If destination is one of the previous instructions
    if (instructions.find(dst) != instructions.end()) {
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

void Restruc::CFGraph::merge(CFGraph &other)
{
    instructions.merge(other.instructions);
    impl::merge_keeping_src_unique(inner_jumps, other.inner_jumps);
    impl::merge_keeping_src_unique(outer_jumps, other.outer_jumps);
    impl::merge_keeping_src_unique(unknown_jumps, other.unknown_jumps);
    impl::merge_keeping_src_unique(calls, other.calls);
}

bool Restruc::CFGraph::is_inside(Address address) const
{
    return instructions.find(address) != instructions.end()
           || inner_jumps.find(address) != inner_jumps.end();
}

Restruc::Restruc(std::filesystem::path const &pe_path)
    : pe_(pe_path)
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
#ifndef NDEBUG
        dump_instruction(std::clog,
                         pe_.raw_to_virtual_address(address),
                         instruction);
#endif

        cfgraph.add_instruction(address, instruction);
        auto analysis_status = cfgraph.analyze(address);
        next_address = analysis_status.next_address;
    }
}

void Restruc::resolve_incomplete_cfgraph(CFGraph &outer_cfgraph)
{
    if (outer_cfgraph.instructions.empty()
        || outer_cfgraph.unknown_jumps.empty()) {
        return;
    }
    while (!outer_cfgraph.unknown_jumps.empty()) {
        auto const unknown_jump_dst =
            outer_cfgraph.unknown_jumps.begin()->first;
        auto new_cfgraph =
            std::make_unique<CFGraph>(unknown_jump_dst, &outer_cfgraph);
        Address address;
        Address next_address = new_cfgraph->entry_point;
        Address end = pe_.get_end(new_cfgraph->entry_point);
        bool done = false;
        while (!done) {
            address = next_address;
            if (address == nullptr || address >= end) {
                break;
            }

            ZydisDecodedInstruction instruction;
            ZYAN_THROW(ZydisDecoderDecodeBuffer(&decoder_,
                                                address,
                                                end - address,
                                                &instruction));
#ifndef NDEBUG
            dump_instruction(std::clog,
                             pe_.raw_to_virtual_address(address),
                             instruction);
#endif

            new_cfgraph->add_instruction(address, instruction);
            auto analysis_status = new_cfgraph->analyze(address);
            next_address = analysis_status.next_address;
            switch (analysis_status.status) {
            case CFGraph::Next: break;
            case CFGraph::UnknownJump:
                outer_cfgraph.potential_sub_cfgraphs.add(
                    std::move(new_cfgraph));
                done = true;
                break;
            case CFGraph::InnerJump:
            case CFGraph::Complete:
                // can_merge = new_cfgraph->can_merge_with_outer_cfgraph();
                outer_cfgraph.merge(*new_cfgraph);
                done = true;
                break;
            case CFGraph::OuterJump:
                outer_cfgraph.promote_unknown_jump(unknown_jump_dst,
                                                   Jump::Outer);
                done = true;
                break;
            }
        }
    }
}

void Restruc::create_function(Address entry_point)
{
    // Prevent recursive analysis
    if (functions_.find(entry_point) != functions_.end()) {
        return;
    }

    Address address = entry_point;
    auto cfgraph = std::make_unique<CFGraph>(entry_point);
    while (true) {
        fill_cfgraph(*cfgraph);
        if (cfgraph->is_complete()) {
            break;
        }
        resolve_incomplete_cfgraph(*cfgraph);
    }

    functions_.emplace(entry_point, std::move(cfgraph));
    unanalyzed_functions_.push_back(entry_point);
}

Address Restruc::pop_unanalyzed_function()
{
    auto address = unanalyzed_functions_.front();
    unanalyzed_functions_.pop_front();
    return address;
}

void Restruc::analyze()
{
    create_function(pe_.get_entry_point());
    while (!unanalyzed_functions_.empty()) {
        auto &function = functions_[pop_unanalyzed_function()];

        // Iterate over unique call destinations
        for (auto it = function->calls.begin(), end = function->calls.end();
             it != end;
             it = function->calls.upper_bound(it->first)) {
            create_function(it->second.dst);
        }

        // Iterate over unique outer jumps
        for (auto it = function->outer_jumps.begin(),
                  end = function->outer_jumps.end();
             it != end;
             it = function->outer_jumps.upper_bound(it->first)) {
            create_function(it->second.dst);
        }
    }
}

#ifndef NDEBUG

void Restruc::debug(std::ostream &os)
{
    auto address = pe_.virtual_to_raw_address(0x182D0);
    create_function(address);
    dump_function(os, formatter_, *functions_[address]);
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

void Restruc::dump_function(std::ostream &os,
                            ZydisFormatter const &formatter,
                            CFGraph const &function)
{
    char buffer[256];
    os << std::hex << std::setfill('0');
    os << std::setw(8) << pe_.raw_to_virtual_address(function.entry_point)
       << ":\n";
    for (auto const &[address, instruction] : function.instructions) {
        auto va = pe_.raw_to_virtual_address(address);
        dump_instruction(os, va, instruction);
    }
    os << '\n';
}

#endif
