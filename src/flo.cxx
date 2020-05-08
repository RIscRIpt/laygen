#include "flo.hxx"

#include "utils/adapters.hxx"

#include <iterator>

using namespace rstc;

Flo::Flo(Address entry_point)
    : entry_point(entry_point)
{
}

Flo::AnalysisResult
Flo::analyze(Address address, Instruction instr, std::optional<Address> flo_end)
{
    auto [it, inserted] = disassembly_.emplace(address, std::move(instr));
    if (!inserted) {
        return { AlreadyAnalyzed, nullptr };
    }
    auto const &instruction = *it->second;
    Address next_address = address + instruction.length;
    visit(address);
    if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL) {
        if (auto dst = get_call_destination(address, instruction); dst) {
            add_call(dst, address, next_address);
        }
    }
    else if (instruction.mnemonic == ZYDIS_MNEMONIC_RET) {
        if (!flo_end && !is_inside(next_address)
            && !promote_unknown_jumps(next_address, Jump::Inner)) {
            return { Complete, next_address };
        }
    }
    else if (instruction.mnemonic == ZYDIS_MNEMONIC_JMP
             || is_conditional_jump(instruction.mnemonic)) {
        bool unconditional = instruction.mnemonic == ZYDIS_MNEMONIC_JMP;
        Jump::Type type = Jump::Unknown;
        auto dst = get_jump_destination(address, instruction);
        if (dst) {
            type = get_jump_type(dst,
                                 address,
                                 next_address,
                                 unconditional,
                                 flo_end);
            add_jump(type, dst, address);
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
                    return { InnerJump, next_address };
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
    default:
        // Not Jxx / LOOPxx
        return false;
    }
}

std::vector<Context const *> Flo::get_contexts(Address address) const
{
    std::vector<Context const *> contexts;
    auto range = utils::in_range(contexts_.equal_range(address));
    contexts.reserve(std::distance(range.begin(), range.end()));
    for (auto const &[addr, ctx] : range) {
        contexts.push_back(&ctx);
    }
    return contexts;
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
            add_jump(type, ijump->second.dst, ijump->second.src);
            ijump = unknown_jumps_.erase(ijump);
        }
        else {
            ++ijump;
        }
    }
}

void Flo::filter_contexts(Address address, Contexts &contexts)
{
    // Compare contexts with existing contexts, eliminating duplicates.
    // It should be enough to filter once per basic block.
    contexts.remove_multimap_duplicates(contexts_, address);
}

Flo::ContextPropagationResult Flo::propagate_contexts(Address address,
                                                      Contexts contexts)
{
    ContextPropagationResult result;
    auto it_instr = disassembly_.find(address);
    if (it_instr == disassembly_.end()) {
        return result;
    }
    result.instruction = &*it_instr->second;
    while (!contexts.empty()) {
        auto const &context =
            emplace_context(address, contexts.pop());
        auto new_context = context.make_child(Context::ParentRole::Default);
        emulate(address, *result.instruction, new_context);
        result.new_contexts.emplace(std::move(new_context));
    }
    return result;
}

Context const &Flo::emplace_context(Address address, Context &&context)
{
    auto range = utils::in_range(contexts_.equal_range(address));
    auto insert_hint = std::upper_bound(range.begin(),
                                        range.end(),
                                        context.get_hash(),
                                        [](size_t hash, auto const &it) {
                                            return hash < it.second.get_hash();
                                        });
    auto emplaced = contexts_.emplace_hint(insert_hint,
                                           address,
                                           std::forward<Context>(context));
    return emplaced->second;
}

void Flo::emulate(Address address,
                  ZydisDecodedInstruction const &instruction,
                  Context &context)
{
    assert(address);
    for (size_t i = 0; i < instruction.operand_count; i++) {
        auto const &op = instruction.operands[i];
        if (!(op.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE)) {
            continue;
        }
        switch (op.type) {
        case ZYDIS_OPERAND_TYPE_REGISTER:
            // TODO: analyze source, and set source value
            context.set(op.reg.value, address);
            break;
        case ZYDIS_OPERAND_TYPE_MEMORY:
            if (auto [value, size] = get_memory_address(op, context); value) {
                context.set(*value, size, address);
            }
            break;
        default: break;
        }
    }
}

ZydisDecodedInstruction const *Flo::get_instruction(Address address) const
{
    if (auto it = disassembly_.find(address); it != disassembly_.end()) {
        return it->second.get();
    }
    return nullptr;
}

void Flo::add_jump(Jump::Type type, Address dst, Address src)
{
    switch (type) {
    case Jump::Inner:
        inner_jumps_.emplace(dst, Jump(Jump::Inner, dst, src));
        break;
    case Jump::Outer:
        outer_jumps_.emplace(dst, Jump(Jump::Outer, dst, src));
        break;
    case Jump::Unknown:
        unknown_jumps_.emplace(dst, Jump(Jump::Unknown, dst, src));
        break;
    }
}

void Flo::add_call(Address dst, Address src, Address ret)
{
    calls_.emplace(src, Call(dst, src, ret));
}

bool Flo::promote_unknown_jumps(Address dst, Jump::Type new_type)
{
    bool promoted = false;
    while (true) {
        if (auto jump = unknown_jumps_.extract(dst); !jump.empty()) {
            promoted = true;
            add_jump(new_type, dst, jump.mapped().src);
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

Jump::Type Flo::get_jump_type(Address dst,
                              Address src,
                              Address next,
                              bool unconditional,
                              std::optional<Address> flo_end) const
{
    // If we have end of flo,
    // we can easily check whether it is inner or outer jump
    if (flo_end) {
        if (dst >= entry_point && dst < flo_end) {
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

bool Flo::is_inside(Address address, std::optional<Address> flo_end) const
{
    if (flo_end) {
        return address >= entry_point && address < flo_end;
    }
    return disassembly_.contains(address) || inner_jumps_.contains(address);
}

Address Flo::get_jump_destination(Address address,
                                  ZydisDecodedInstruction const &instruction)
{
    assert(instruction.mnemonic == ZYDIS_MNEMONIC_JMP
           || is_conditional_jump(instruction.mnemonic));
    assert(instruction.operand_count > 0);
    auto const &op = instruction.operands[0];
    // TODO: Support more op.type-s.
    switch (op.type) {
    case ZYDIS_OPERAND_TYPE_IMMEDIATE:
        return address + instruction.length + op.imm.value.s;
    default: return nullptr;
    }
}

std::vector<Address>
Flo::get_jump_destinations(PE const &pe,
                           Address address,
                           ZydisDecodedInstruction const &instruction,
                           Contexts const &contexts)
{
    assert(instruction.mnemonic == ZYDIS_MNEMONIC_JMP
           || is_conditional_jump(instruction.mnemonic));
    assert(instruction.operand_count > 0);
    std::vector<Address> dsts;
    auto const &op = instruction.operands[0];
    switch (op.type) {
    case ZYDIS_OPERAND_TYPE_IMMEDIATE:
        dsts.push_back(address + instruction.length + op.imm.value.s);
        break;
    case ZYDIS_OPERAND_TYPE_REGISTER:
        dsts.reserve(contexts.size());
        for (auto const &context : contexts) {
            if (auto va_dst = context.get(op.reg.value);
                va_dst && va_dst->value) {
                if (auto dst = pe.virtual_to_raw_address(*va_dst->value); dst) {
                    dsts.push_back(dst);
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

std::pair<Context::Value, size_t>
Flo::get_memory_address(ZydisDecodedOperand const &op, Context const &context)
{
    assert(op.type == ZYDIS_OPERAND_TYPE_MEMORY);
    Context::Value::value_type value = 0;
    if (op.mem.base != ZYDIS_REGISTER_NONE
        && op.mem.base != ZYDIS_REGISTER_RIP) {
        if (auto base = context.get(op.mem.base); base && base->value) {
            value += *base->value;
        }
        else {
            return { std::nullopt, 0 };
        }
    }
    if (op.mem.disp.has_displacement) {
        value += op.mem.disp.value;
    }
    if (op.mem.index != ZYDIS_REGISTER_NONE) {
        if (auto index = context.get(op.mem.index); index && index->value) {
            value += *index->value * op.mem.scale;
        }
        else {
            return { std::nullopt, 0 };
        }
    }
    return { value, 8 };
}
