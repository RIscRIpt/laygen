#include "flo.hxx"

#include "utils/adapters.hxx"

#include <iterator>

using namespace rstc;

Flo::Flo(PE const &pe,
         Address entry_point,
         Address reference,
         std::optional<Address> end)
    : entry_point(entry_point)
    , end_(end)
    , pe_(pe)
{
    add_reference(reference);
}

Flo::AnalysisResult Flo::analyze(Address address, Instruction instr)
{
    if (should_be_unreachable(*instr)) {
        return { Unreachable, nullptr };
    }
    auto [it, inserted] = disassembly_.emplace(address, std::move(instr));
    if (!inserted) {
        return { AlreadyAnalyzed, nullptr };
    }
    auto const &instruction = *it->second;
    Address next_address = address + instruction.length;
    visit(address);
    if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL) {
        if (auto dst = get_call_destination(address, instruction); dst) {
            add_call(instruction, dst, address, next_address);
        }
    }
    else if (instruction.mnemonic == ZYDIS_MNEMONIC_RET) {
        if (!is_inside(next_address)
            && !promote_unknown_jumps(next_address, Jump::Inner)) {
            return { Complete, next_address };
        }
    }
    else if (is_any_jump(instruction.mnemonic)) {
        bool unconditional = instruction.mnemonic == ZYDIS_MNEMONIC_JMP;
        Jump::Type type = Jump::Unknown;
        auto dst = get_jump_destination(address, instruction);
        if (dst) {
            type = get_jump_type(dst, address, next_address, unconditional);
            add_jump(type, instruction, dst, address);
        }
        if (unconditional) {
            switch (type) {
            case Jump::Unknown:
                if (!promote_unknown_jumps(next_address, Jump::Inner)) {
                    return { UnknownJump, next_address };
                }
                break;
            case Jump::Inner:
                if (!is_inside(next_address)) {
                    // Prevent analysis cycle
                    if (dst <= address) {
                        return { CycleJump, next_address };
                    }
                    return { InnerJump, dst };
                }
                break;
            case Jump::Outer:
                assert(!is_inside(dst));
                return { OuterJump, next_address };
            }
        }
    }
    else {
        auto sp_status = analyze_stack_pointer_manipulation(instruction);
        if (sp_status == SPModified) {
            stack_depth_was_modified_ = true;
        }
    }
    return { Next, next_address };
}

bool Flo::is_any_jump(ZydisMnemonic mnemonic)
{
    return mnemonic == ZYDIS_MNEMONIC_JMP || is_conditional_jump(mnemonic);
}

bool Flo::is_conditional_jump(ZydisMnemonic mnemonic)
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
    default:
        // Not Jxx / LOOPxx
        return false;
    }
}

ZydisDecodedInstruction const *Flo::get_instruction(Address address) const
{
    if (auto it = disassembly_.find(address); it != disassembly_.end()) {
        return it->second.get();
    }
    return nullptr;
}

std::vector<Cycle const *> Flo::get_cycles(Address address) const
{
    auto it = cycles_.lower_bound(address);
    std::vector<Cycle const *> cycles;
    while (it != cycles_.end()) {
        auto const &cycle = it->second;
        if (address < cycle.first || cycle.last < address) {
            break;
        }
        cycles.push_back(&cycle);
        ++it;
    }
    return cycles;
}

Flo::SPManipulationType Flo::analyze_stack_pointer_manipulation(
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
                    stack_depth_ -= src.imm.value.s;
                    return SPModified;
                case ZYDIS_MNEMONIC_SUB:
                    stack_depth_ += src.imm.value.s;
                    return SPModified;
                default: stack_depth_ = -1; return SPAmbiguous;
                }
            }
            else {
                stack_depth_ = -1;
                return SPAmbiguous;
            }
        }
    }
    else {
        switch (instruction.mnemonic) {
        case ZYDIS_MNEMONIC_PUSH: stack_depth_ += 8; return SPModified;
        case ZYDIS_MNEMONIC_PUSHF: stack_depth_ += 2; return SPModified;
        case ZYDIS_MNEMONIC_PUSHFD: stack_depth_ += 4; return SPModified;
        case ZYDIS_MNEMONIC_PUSHFQ: stack_depth_ += 8; return SPModified;

        case ZYDIS_MNEMONIC_POP: stack_depth_ -= 8; return SPModified;
        case ZYDIS_MNEMONIC_POPF: stack_depth_ -= 2; return SPModified;
        case ZYDIS_MNEMONIC_POPFD: stack_depth_ -= 4; return SPModified;
        case ZYDIS_MNEMONIC_POPFQ: stack_depth_ -= 8; return SPModified;

        default: break;
        }
    }
    return SPUnmodified;
}

Address Flo::get_unanalized_inner_jump_dst() const
{
    for (auto it = inner_jumps_.begin(), end = inner_jumps_.end(); it != end;
         it = inner_jumps_.upper_bound(it->first)) {
        if (!disassembly_.contains(it->first)) {
            return it->first;
        }
    }
    return nullptr;
}

void Flo::promote_unknown_jumps(Jump::Type type,
                                std::function<bool(Address)> predicate)
{
    for (auto ijump = unknown_jumps_.begin(); ijump != unknown_jumps_.end();) {
        if (!predicate || predicate(ijump->second.dst)) {
            auto const &jump = ijump->second;
            add_jump(type, jump.ins, jump.dst, jump.src);
            ijump = unknown_jumps_.erase(ijump);
        }
        else {
            ++ijump;
        }
    }
}

void Flo::set_end(Address end)
{
    disassembly_.erase(disassembly_.lower_bound(end), disassembly_.end());
    end_ = end;
}

bool Flo::modifies_flags_register(ZydisDecodedInstruction const &instruction)
{
    return std::any_of(
        instruction.operands,
        instruction.operands + instruction.operand_count,
        [](ZydisDecodedOperand const &op) {
            if (op.type != ZYDIS_OPERAND_TYPE_REGISTER
                || !(op.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE)) {
                return false;
            }
            switch (op.reg.value) {
            case ZYDIS_REGISTER_FLAGS:
            case ZYDIS_REGISTER_EFLAGS:
            case ZYDIS_REGISTER_RFLAGS:
                //
                return true;
            }
            return false;
        });
}

void Flo::add_cycle(Contexts const &contexts, Address first, Address last)
{
    assert(is_inside(first));
    Cycle::ExitConditions exit_conditions;
    auto it = disassembly_.find(first);
    auto add_exit_condition = [first, &exit_conditions](decltype(it) it) {
        auto jt = it;
        for (; jt->first >= first; --jt) {
            if (modifies_flags_register(*jt->second)) {
                auto const &op = jt->second->operands[0];
                if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    exit_conditions.emplace(
                        std::piecewise_construct,
                        std::forward_as_tuple(
                            virt::Registers::promote(op.reg.value)),
                        std::forward_as_tuple(jt->second.get(),
                                              it->second->mnemonic));
                }
                break;
            }
        }
    };
    while (it->first < last) {
        if (Flo::is_conditional_jump(it->second->mnemonic)) {
            for (auto dst :
                 get_jump_destinations(it->first, *it->second, contexts)) {
                if (dst <= last) {
                    // Jump is not outside cycle
                    goto next;
                }
            }
            add_exit_condition(it);
        }
    next:
        ++it;
    }
    assert(it->first == last);
    if (Flo::is_conditional_jump(it->second->mnemonic)) {
        add_exit_condition(it);
    }
    cycles_.emplace(
        std::piecewise_construct,
        std::forward_as_tuple(last),
        std::forward_as_tuple(first, last, std::move(exit_conditions)));
}

void Flo::add_reference(Address reference)
{
    if (reference) {
        references_.insert(reference);
    }
}

void Flo::add_jump(Jump::Type type,
                   ZydisDecodedInstruction const &ins,
                   Address dst,
                   Address src)
{
    switch (type) {
    case Jump::Inner:
        inner_jumps_.emplace(dst, Jump(Jump::Inner, ins, dst, src));
        break;
    case Jump::Outer:
        outer_jumps_.emplace(dst, Jump(Jump::Outer, ins, dst, src));
        break;
    case Jump::Unknown:
        unknown_jumps_.emplace(dst, Jump(Jump::Unknown, ins, dst, src));
        break;
    }
}

void Flo::add_call(ZydisDecodedInstruction const &ins,
                   Address dst,
                   Address src,
                   Address ret)
{
    calls_.emplace(dst, Call(ins, dst, src, ret));
}

bool Flo::promote_unknown_jumps(Address dst, Jump::Type new_type)
{
    bool promoted = false;
    while (true) {
        if (auto hjump = unknown_jumps_.extract(dst); !hjump.empty()) {
            promoted = true;
            auto const &jump = hjump.mapped();
            add_jump(new_type, jump.ins, dst, jump.src);
        }
        else {
            break;
        }
    }
    return promoted;
}

void Flo::visit(Address address)
{
    promote_unknown_jumps(address, Jump::Inner);
}

bool Flo::should_be_unreachable(ZydisDecodedInstruction const &instruction)
{
    switch (instruction.mnemonic) {
    case ZYDIS_MNEMONIC_INT3: return true;
    }
    return false;
}

Jump::Type Flo::get_jump_type(Address dst,
                              Address src,
                              Address next,
                              bool unconditional) const
{
    // If we have end of flo,
    // we can easily check whether it is inner or outer jump
    if (end_) {
        if (dst >= entry_point && dst < end_) {
            return Jump::Inner;
        }
        return Jump::Outer;
    }
    // If jumping with offset 0, i.e. no jump
    if (dst == next) {
        return Jump::Inner;
    }
    // If destination is one of known destinations
    if (inner_jumps_.contains(dst)) {
        return Jump::Inner;
    }
    if (outer_jumps_.contains(dst)) {
        return Jump::Outer;
    }
    // If jump is first flo instruction
    if (disassembly_.size() == 1 && unconditional) {
        // Assume JMP table
        return Jump::Outer;
    }
    // If destination is one of the previous instructions
    if (disassembly_.contains(dst)) {
        return Jump::Inner;
    }
    // If jumping above entry-point
    if (dst < entry_point) {
        // Assume no inner jumps are made above entry-point
        return Jump::Outer;
    }
    if (!stack_depth_is_ambiguous()) {
        if (stack_depth_ != 0) {
            // Assume no outer jumps are made with dirty stack
            return Jump::Inner;
        }
        else {
            // If stack depth was modified previously, and returned to 0
            // Assume outer jump (optimized tail call).
            if (stack_depth_was_modified_) {
                return Jump::Outer;
            }
        }
    }
    return Jump::Unknown;
}

bool Flo::stack_depth_is_ambiguous() const
{
    return stack_depth_ == -1;
}

bool Flo::is_inside(Address address) const
{
    return disassembly_.contains(address) || inner_jumps_.contains(address);
}

Address Flo::get_jump_destination(Address address,
                                  ZydisDecodedInstruction const &instruction)
{
    assert(is_any_jump(instruction.mnemonic));
    assert(instruction.operand_count > 0);
    auto const &op = instruction.operands[0];
    // TODO: Support more op.type-s.
    switch (op.type) {
    case ZYDIS_OPERAND_TYPE_IMMEDIATE:
        return address + instruction.length + op.imm.value.s;
    default: return nullptr;
    }
}

std::unordered_set<Address>
Flo::get_jump_destinations(Address address,
                           ZydisDecodedInstruction const &instruction,
                           Contexts const &contexts)
{
    assert(is_any_jump(instruction.mnemonic));
    assert(instruction.operand_count > 0);
    std::unordered_set<Address> dsts;
    auto const &op = instruction.operands[0];
    switch (op.type) {
    case ZYDIS_OPERAND_TYPE_IMMEDIATE:
        dsts.emplace(address + instruction.length + op.imm.value.s);
        break;
    case ZYDIS_OPERAND_TYPE_REGISTER:
        dsts.reserve(contexts.size());
        for (auto const &context : contexts) {
            if (auto va_dst = context.get_register(op.reg.value);
                va_dst && !va_dst->is_symbolic()) {
                if (auto dst = pe_.virtual_to_raw_address(va_dst->value());
                    dst) {
                    dsts.emplace(dst);
                }
            }
        }
        break;
    default: break;
    }
    return dsts;
}

Address Flo::get_call_destination(Address address,
                                  ZydisDecodedInstruction const &instruction)
{
    assert(instruction.mnemonic == ZYDIS_MNEMONIC_CALL);
    assert(instruction.operand_count > 0);
    // Assume calls always return (i.e. they are not no-return)
    auto const &op = instruction.operands[0];
    switch (op.type) {
    case ZYDIS_OPERAND_TYPE_IMMEDIATE:
        return address + instruction.length + op.imm.value.s;
    default: return nullptr;
    }
}
