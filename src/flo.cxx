#include "flo.hxx"

#include "utils/adapters.hxx"

#include <iterator>

using namespace rstc;

std::unordered_map<ZydisMnemonic, Flo::EmulationCallbackAction>
    Flo::emulation_callback_actions_{
        { ZYDIS_MNEMONIC_ADD,
          [](uintptr_t dst, uintptr_t src) { return dst + src; } },
        { ZYDIS_MNEMONIC_SUB,
          [](uintptr_t dst, uintptr_t src) { return dst - src; } },
        { ZYDIS_MNEMONIC_OR,
          [](uintptr_t dst, uintptr_t src) { return dst | src; } },
        { ZYDIS_MNEMONIC_AND,
          [](uintptr_t dst, uintptr_t src) { return dst & src; } },
        { ZYDIS_MNEMONIC_XOR,
          [](uintptr_t dst, uintptr_t src) { return dst ^ src; } },
        { ZYDIS_MNEMONIC_IMUL,
          [](uintptr_t dst, uintptr_t src) { return dst * src; } },
    };

Flo::Flo(PE const &pe, Address entry_point, std::optional<Address> end)
    : entry_point(entry_point)
    , end(end)
    , pe_(pe)
{
}

Flo::AnalysisResult Flo::analyze(Address address, Instruction instr)
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
        if (!end && !is_inside(next_address)
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
            type = get_jump_type(dst, address, next_address, unconditional);
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
                    if (!end) {
                        next_address = dst;
                    }
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
        auto const &context = emplace_context(address, contexts.pop());
        auto new_context = context.make_child();
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

    // Operations with:
    // * (A)L, (A)H, (A)X / 8, 16 bits - do not affect HO bits
    // * E(A)X / 32 bits - zerorize HO bits.

    using namespace std::placeholders;

    switch (instruction.mnemonic) {
    case ZYDIS_MNEMONIC_MOV: {
        emulate_instruction(
            instruction,
            context,
            address,
            [](virt::Value const &dst, virt::Value const &src) -> virt::Value {
                uintptr_t mask = ~0;
                if (dst.size() < 8) {
                    mask = (1ULL << (dst.size() * 8)) - 1;
                }
                if (!dst.is_symbolic() && !src.is_symbolic()
                    && dst.size() < 4) {
                    return virt::make_value(src.source(),
                                            (dst.value() & ~mask)
                                                | (src.value() & mask),
                                            dst.size());
                }
                else if (!src.is_symbolic()) {
                    return virt::make_value(src.source(),
                                            src.value() & mask,
                                            dst.size());
                }
                else {
                    return src;
                }
            });
    } break;
    case ZYDIS_MNEMONIC_ADD:
    case ZYDIS_MNEMONIC_SUB:
    case ZYDIS_MNEMONIC_OR:
    case ZYDIS_MNEMONIC_AND:
    case ZYDIS_MNEMONIC_XOR:
    case ZYDIS_MNEMONIC_IMUL: {
        auto action = emulation_callback_actions_.at(instruction.mnemonic);
        auto callback =
            std::bind(&Flo::emulate_instruction_helper, _1, _2, action);
        emulate_instruction(instruction, context, address, callback);
    } break;
    case ZYDIS_MNEMONIC_LEA:
        emulate_instruction_lea(instruction, context, address);
        break;
    case ZYDIS_MNEMONIC_PUSH:
        emulate_instruction_push(instruction, context, address);
        break;
    case ZYDIS_MNEMONIC_POP:
        emulate_instruction_pop(instruction, context, address);
        break;
    case ZYDIS_MNEMONIC_CALL:
        emulate_instruction_call(instruction, context, address);
        break;
    case ZYDIS_MNEMONIC_RET:
        emulate_instruction_ret(instruction, context, address);
        break;
    case ZYDIS_MNEMONIC_INC:
        emulate_instruction_inc(instruction, context, address, +1);
        break;
    case ZYDIS_MNEMONIC_DEC:
        emulate_instruction_inc(instruction, context, address, -1);
        break;
    default:
        for (size_t i = 0; i < instruction.operand_count; i++) {
            auto const &op = instruction.operands[i];
            if (!(op.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE)) {
                continue;
            }
            switch (op.type) {
            case ZYDIS_OPERAND_TYPE_REGISTER:
                context.set_register(
                    op.reg.value,
                    virt::make_symbolic_value(address, op.element_size / 8));
                break;
            case ZYDIS_OPERAND_TYPE_MEMORY:
                if (auto value = get_memory_address(op, context); value) {
                    context.set_memory(
                        *value,
                        virt::make_symbolic_value(address,
                                                  op.element_size / 8));
                }
                break;
            default: break;
            }
        }
        break;
    }
}

void Flo::emulate_instruction(ZydisDecodedInstruction const &instruction,
                              Context &context,
                              Address address,
                              EmulationCallback const &callback)
{
    Operand dst = get_operand(instruction.operands[0], context, address);
    Operand src;
    virt::Value imm;
    int op_count = 1;
    if (instruction.operand_count >= 2) {
        op_count = 2;
        if (auto op2 = instruction.operands[1];
            op2.visibility == ZYDIS_OPERAND_VISIBILITY_EXPLICIT) {
            src = get_operand(op2, context, address);
        }
    }
    if (instruction.operand_count >= 3) {
        if (auto op3 = instruction.operands[2];
            op3.visibility == ZYDIS_OPERAND_VISIBILITY_EXPLICIT) {
            op_count = 3;
            if (op3.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                imm = get_operand(op3, context, address).value;
            }
        }
    }
    if (instruction.mnemonic == ZYDIS_MNEMONIC_XOR && dst.reg == src.reg) {
        dst.value = virt::make_value(address,
                                     0,
                                     instruction.operands[1].element_size / 8);
    }
    else {
        if (op_count == 2) {
            dst.value = callback(dst.value, src.value);
        }
        else if (instruction.operands[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            // TODO: use dst, if needed
            // for now, assume it's unused.
            dst.value = callback(src.value, imm);
        }
        else {
            dst.value = virt::make_symbolic_value(address, dst.value.size());
        }
    }
    dst.value.set_source(address);
    if (dst.reg != ZYDIS_REGISTER_NONE) {
        context.set_register(dst.reg, dst.value);
    }
    else if (dst.address) {
        context.set_memory(*dst.address, dst.value);
    }
}

void Flo::emulate_instruction_lea(ZydisDecodedInstruction const &instruction,
                                  Context &context,
                                  Address address)
{
    Operand dst = get_operand(instruction.operands[0], context, address);
    Operand src = get_operand(instruction.operands[1], context, address);
    assert(dst.reg != ZYDIS_REGISTER_NONE);
    if (src.address) {
        context.set_register(dst.reg, virt::make_value(address, *src.address));
    }
}

void Flo::emulate_instruction_push(ZydisDecodedInstruction const &instruction,
                                   Context &context,
                                   Address address)
{
    assert(instruction.mnemonic == ZYDIS_MNEMONIC_PUSH);
    if (auto rsp = context.get_register(ZYDIS_REGISTER_RSP);
        rsp && !rsp->is_symbolic()) {
        auto new_rsp = rsp->value() - 8;
        auto op = get_operand(instruction.operands[0], context, address);
        op.value.set_source(address);
        context.set_register(ZYDIS_REGISTER_RSP,
                             virt::make_value(address, new_rsp));
        context.set_memory(new_rsp, op.value);
    }
}

void Flo::emulate_instruction_pop(ZydisDecodedInstruction const &instruction,
                                  Context &context,
                                  Address address)
{
    assert(instruction.mnemonic == ZYDIS_MNEMONIC_POP);
    if (auto rsp = context.get_register(ZYDIS_REGISTER_RSP);
        rsp && !rsp->is_symbolic()) {
        auto new_rsp = rsp->value() + 8;
        context.set_register(ZYDIS_REGISTER_RSP,
                             virt::make_value(address, new_rsp));
        auto op = get_operand(instruction.operands[0], context, address);
        op.value.set_source(address);
        if (op.reg != ZYDIS_REGISTER_NONE) {
            context.set_register(op.reg, op.value);
        }
        else if (op.address) {
            context.set_memory(*op.address, op.value);
        }
    }
}

void Flo::emulate_instruction_call(ZydisDecodedInstruction const &instruction,
                                   Context &context,
                                   Address address)
{
    assert(instruction.mnemonic == ZYDIS_MNEMONIC_CALL);
    if (auto rsp = context.get_register(ZYDIS_REGISTER_RSP);
        rsp && !rsp->is_symbolic()) {
        auto new_rsp = rsp->value() - 8;
        auto return_address =
            pe_.raw_to_virtual_address(address + instruction.length);
        context.set_memory(new_rsp, virt::make_value(address, return_address));
        context.set_register(ZYDIS_REGISTER_RSP,
                             virt::make_value(address, new_rsp));
    }
}

void Flo::emulate_instruction_ret(ZydisDecodedInstruction const &instruction,
                                  Context &context,
                                  Address address)
{
    assert(instruction.mnemonic == ZYDIS_MNEMONIC_RET);
    if (auto rsp = context.get_register(ZYDIS_REGISTER_RSP);
        rsp && !rsp->is_symbolic()) {
        auto new_rsp = rsp->value() + 8;
        context.set_register(ZYDIS_REGISTER_RSP,
                             virt::make_value(address, new_rsp));
    }
}

void Flo::emulate_instruction_inc(ZydisDecodedInstruction const &instruction,
                                  Context &context,
                                  Address address,
                                  int offset)
{
    assert(instruction.mnemonic == ZYDIS_MNEMONIC_INC
           || instruction.mnemonic == ZYDIS_MNEMONIC_DEC);
    Operand dst = get_operand(instruction.operands[0], context, address);
    virt::Value result;
    if (!dst.value.is_symbolic()) {
        result = virt::make_value(address, dst.value.value() + offset);
    }
    else {
        result = virt::make_symbolic_value(address,
                                           8,
                                           dst.value.symbol().offset() + offset,
                                           dst.value.symbol().id());
    }
    if (dst.reg != ZYDIS_REGISTER_NONE) {
        context.set_register(dst.reg, result);
    }
    else if (dst.address) {
        context.set_memory(*dst.address, result);
    }
}

virt::Value Flo::emulate_instruction_helper(
    virt::Value const &dst,
    virt::Value const &src,
    std::function<uintptr_t(uintptr_t, uintptr_t)> action)
{
    if (!dst.is_symbolic() && !src.is_symbolic()) {
        uintptr_t mask = ~0;
        if (dst.size() < 8) {
            mask = (1ULL << (dst.size() * 8)) - 1;
        }
        if (dst.size() < 4) {
            return virt::make_value(
                src.source(),
                (dst.value() & ~mask)
                    | (action(dst.value(), src.value()) & mask),
                dst.size());
        }
        else {
            return virt::make_value(src.source(),
                                    action(dst.value(), src.value()) & mask,
                                    dst.size());
        }
    }
    else if (dst.is_symbolic() && !src.is_symbolic()) {
        return virt::make_symbolic_value(src.source(),
                                         dst.size(),
                                         action(dst.symbol().offset(), src.value()),
                                         dst.symbol().id());
    }
    return virt::make_symbolic_value(src.source(), dst.size());
}

Flo::Operand Flo::get_operand(ZydisDecodedOperand const &operand,
                              Context const &context,
                              Address source)
{
    Operand op;
    switch (operand.type) {
    case ZYDIS_OPERAND_TYPE_IMMEDIATE: {
        op.value = virt::make_value(
            source,
            operand.imm.is_signed ? operand.imm.value.s : operand.imm.value.u,
            operand.element_size / 8);
    } break;
    case ZYDIS_OPERAND_TYPE_REGISTER: {
        op.reg = operand.reg.value;
        if (auto valsrc = context.get_register(op.reg); valsrc) {
            op.value = *valsrc;
            op.value.set_size(operand.element_size / 8);
        }
        else {
            op.value =
                virt::make_symbolic_value(source, operand.element_size / 8);
        }
    } break;
    case ZYDIS_OPERAND_TYPE_MEMORY: {
        op.address = get_memory_address(operand, context);
        if (op.address && operand.element_size) {
            op.value =
                context.get_memory(*op.address, operand.element_size / 8);
        }
        else {
            op.value =
                virt::make_symbolic_value(source, operand.element_size / 8);
        }
    } break;
    default:
        op.value = virt::make_symbolic_value(source, operand.element_size / 8);
        break;
    }
    return op;
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
    calls_.emplace(dst, Call(dst, src, ret));
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
                              bool unconditional) const
{
    // If we have end of flo,
    // we can easily check whether it is inner or outer jump
    if (end) {
        if (dst >= entry_point && dst < end) {
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
    if (end) {
        return address >= entry_point && address < end;
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

std::unordered_set<Address>
Flo::get_jump_destinations(PE const &pe,
                           Address address,
                           ZydisDecodedInstruction const &instruction,
                           Contexts const &contexts)
{
    assert(instruction.mnemonic == ZYDIS_MNEMONIC_JMP
           || is_conditional_jump(instruction.mnemonic));
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
                if (auto dst = pe.virtual_to_raw_address(va_dst->value());
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

std::optional<uintptr_t> Flo::get_memory_address(ZydisDecodedOperand const &op,
                                                 Context const &context)
{
    assert(op.type == ZYDIS_OPERAND_TYPE_MEMORY);
    uintptr_t value = 0;
    if (op.mem.base != ZYDIS_REGISTER_NONE
        && op.mem.base != ZYDIS_REGISTER_RIP) {
        if (auto base = context.get_register(op.mem.base);
            base && !base->is_symbolic()) {
            value += base->value();
        }
        else {
            return std::nullopt;
        }
    }
    if (op.mem.disp.has_displacement) {
        value += op.mem.disp.value;
    }
    if (op.mem.index != ZYDIS_REGISTER_NONE) {
        if (auto index = context.get_register(op.mem.index);
            index && !index->is_symbolic()) {
            value += index->value() * op.mem.scale;
        }
        else {
            return std::nullopt;
        }
    }
    return value;
}
