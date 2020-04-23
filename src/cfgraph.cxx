#include "cfgraph.hxx"

using namespace rstc;

CFGraph::CFGraph(Address entry_point)
    : entry_point(entry_point)
{
}

CFGraph::AnalysisResult
CFGraph::analyze(PE &pe, Address address, Instruction instr)
{
    auto result = disassembly.emplace(address, std::move(instr));
    auto const &instruction = *result.first->second;
    Address next_address = address + instruction.length;
    visit(address);
    if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL) {
        // Assume calls always return (i.e. they are not no-return)
        auto const &op = instruction.operands[0];
        switch (op.type) {
        case ZYDIS_OPERAND_TYPE_IMMEDIATE:
            add_call(next_address + instruction.operands[0].imm.value.s,
                     address,
                     next_address);
            break;
            /*
        case ZYDIS_OPERAND_TYPE_MEMORY:
            if (op.mem.type == ZYDIS_MEMOP_TYPE_MEM
                && op.mem.segment == ZYDIS_REGISTER_DS
                && op.mem.base == ZYDIS_REGISTER_RIP
                && op.mem.index == ZYDIS_REGISTER_NONE && op.mem.scale == 0
                && op.mem.disp.has_displacement) {
                Address dst_addr = next_address + op.mem.disp.value;
                Address dst = *reinterpret_cast<Address *>(dst_addr); // dst is
        invalid (virtual / without relocation) if (dst != nullptr) {
                    add_call(dst, address, next_address);
                }
            }
            break;
            */
        }
    }
    else if (instruction.mnemonic == ZYDIS_MNEMONIC_RET) {
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
            type = get_jump_type(dst, address, next_address, unconditional);
            add_jump(type, dst, address);
        }
        else {
            return { UnknownJump, nullptr };
        }
        // TODO: Support more op.type-s.
        if (unconditional) {
            switch (type) {
            case Jump::Unknown:
                if (!promote_unknown_jumps(next_address, Jump::Inner)) {
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

bool CFGraph::is_conditional_jump(ZydisMnemonic mnemonic)
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

CFGraph::SPManipulationType CFGraph::analyze_stack_pointer_manipulation(
    ZydisDecodedInstruction const &instruction)
{
    if (stack_depth_is_ambiguous()) {
        return SPAmbiguous;
    }
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

Address CFGraph::get_unanalized_inner_jump_dst() const
{
    for (auto it = inner_jumps.begin(), end = inner_jumps.end(); it != end;
         it = inner_jumps.upper_bound(it->first)) {
        if (!disassembly.contains(it->first)) {
            return it->first;
        }
    }
    return nullptr;
}

void rstc::CFGraph::promote_unknown_jumps(
    Jump::Type type,
    std::function<bool(Address)> predicate)
{
    for (auto ijump = unknown_jumps.begin(); ijump != unknown_jumps.end();) {
        if (!predicate || predicate(ijump->second.dst)) {
            add_jump(type, ijump->second.dst, ijump->second.src);
            ijump = unknown_jumps.erase(ijump);
        }
        else {
            ++ijump;
        }
    }
}

void CFGraph::add_jump(Jump::Type type, Address dst, Address src)
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

void CFGraph::add_call(Address dst, Address src, Address ret)
{
    calls.emplace(src, Call(dst, src, ret));
}

bool CFGraph::promote_unknown_jumps(Address dst, Jump::Type new_type)
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

void CFGraph::visit(Address address)
{
    promote_unknown_jumps(address, Jump::Inner);
}

Jump::Type CFGraph::get_jump_type(Address dst, Address src, Address next, bool unconditional) const
{
    // If jumping with offset 0, i.e. no jump
    if (dst == next) {
        return Jump::Inner;
    }
    // If destination is one of known destinations
    if (inner_jumps.contains(dst)) {
        return Jump::Inner;
    }
    if (outer_jumps.contains(dst)) {
        return Jump::Outer;
    }
    // If jump is first cfgraph instruction
    if (disassembly.size() == 1 && unconditional) {
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

bool CFGraph::stack_depth_is_ambiguous() const
{
    return stack_depth == -1;
}

bool CFGraph::is_inside(Address address) const
{
    return disassembly.contains(address) || inner_jumps.contains(address);
}