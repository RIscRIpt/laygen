#include "recontex.hxx"

#include "dumper.hxx"
#include "scope_guard.hxx"
#include "utils/adapters.hxx"

#include <algorithm>
#include <iostream>
#include <iterator>

using namespace rstc;

//#define DEBUG_ANALYSIS_PROGRESS
//#define DEBUG_CONTEXT_PROPAGATION

ZydisRegister const Recontex::volatile_registers_[] = {
    ZYDIS_REGISTER_RAX,  ZYDIS_REGISTER_RCX,  ZYDIS_REGISTER_RDX,
    ZYDIS_REGISTER_R8,   ZYDIS_REGISTER_R9,   ZYDIS_REGISTER_R10,
    ZYDIS_REGISTER_R11,  ZYDIS_REGISTER_ZMM0, ZYDIS_REGISTER_ZMM1,
    ZYDIS_REGISTER_ZMM2, ZYDIS_REGISTER_ZMM3, ZYDIS_REGISTER_ZMM4,
    ZYDIS_REGISTER_ZMM5,
};

ZydisRegister const Recontex::nonvolatile_registers_[] = {
    ZYDIS_REGISTER_RBX,   ZYDIS_REGISTER_RBP,   ZYDIS_REGISTER_RSP,
    ZYDIS_REGISTER_RDI,   ZYDIS_REGISTER_RSI,   ZYDIS_REGISTER_R12,
    ZYDIS_REGISTER_R13,   ZYDIS_REGISTER_R14,   ZYDIS_REGISTER_R15,
    ZYDIS_REGISTER_ZMM6,  ZYDIS_REGISTER_ZMM7,  ZYDIS_REGISTER_ZMM8,
    ZYDIS_REGISTER_ZMM9,  ZYDIS_REGISTER_ZMM10, ZYDIS_REGISTER_ZMM11,
    ZYDIS_REGISTER_ZMM12, ZYDIS_REGISTER_ZMM13, ZYDIS_REGISTER_ZMM14,
    ZYDIS_REGISTER_ZMM15,
};

std::unordered_map<ZydisMnemonic, Recontex::EmulationCallbackAction>
    Recontex::emulation_callback_actions_{
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

#ifdef DEBUG_CONTEXT_PROPAGATION

void dump_register_value(std::ostream &os,
                         Dumper const &dumper,
                         Reflo &reflo,
                         Context const &context,
                         ZydisRegister reg)
{
    if (auto changed = context.get_register(reg); changed) {
        auto flo = reflo.get_flo_by_address(changed->source());
        if (flo) {
            if (!changed->is_symbolic()) {
                os << std::setfill('0') << std::hex << ' ' << std::setw(16)
                   << changed->value() << " \n";
            }
            else {
                os << std::setfill('0') << std::hex << '[' << std::setw(16)
                   << changed->symbol().id() << "]\n";
            }
        }
    }
}

#endif

Recontex::Recontex(Reflo &reflo)
    : reflo_(reflo)
    , pe_(reflo.get_pe())
    , max_analyzing_threads_(std::thread::hardware_concurrency())
{
}

void Recontex::analyze()
{
    for (auto const &[address, flo] : reflo_.get_flos()) {
        run_analysis(*flo);
    }
#ifdef DEBUG_ANALYSIS_PROGRESS
    std::clog << "Waiting for analysis to finish ...\n";
#endif
    wait_for_analysis();
#ifdef DEBUG_ANALYSIS_PROGRESS
    std::clog << "Done.\n";
#endif
}

void Recontex::set_max_analyzing_threads(size_t amount)
{
    max_analyzing_threads_ = amount;
}

Recontex::FloContexts const &Recontex::get_contexts(Flo const &flo) const
{
    return contexts_.at(flo.entry_point);
}

std::vector<Context const *> Recontex::get_contexts(Flo const &flo,
                                                    Address address) const
{
    std::vector<Context const *> contexts;
    auto const &flo_contexts = contexts_.at(flo.entry_point);
    auto range = utils::in_range(flo_contexts.equal_range(address));
    contexts.reserve(std::distance(range.begin(), range.end()));
    for (auto const &[addr, ctx] : range) {
        contexts.push_back(&ctx);
    }
    return contexts;
}

void Recontex::run_analysis(Flo &flo)
{
    auto lock = std::unique_lock(analyzing_threads_mutex_);
    analyzing_threads_cv_.wait(lock, [this] {
        return analyzing_threads_count_ < max_analyzing_threads_;
    });
    ++analyzing_threads_count_;
    analyzing_threads_.emplace_back([this, &flo]() mutable {
        ScopeGuard decrement_analyzing_threads_count([this]() noexcept {
            std::scoped_lock<std::mutex> notify_guard(analyzing_threads_mutex_);
            --analyzing_threads_count_;
            analyzing_threads_cv_.notify_all();
        });
#ifdef DEBUG_ANALYSIS_PROGRESS
        std::clog << "Analyzing: " << std::dec << analyzing_threads_.size()
                  << '/' << std::dec << reflo_.get_flos().size() << ": "
                  << std::setfill('0') << std::setw(8) << std::hex
                  << pe_.raw_to_virtual_address(flo.entry_point) << '\n';
#endif
        FloContexts flo_contexts;
        analyze_flo(flo,
                    flo_contexts,
                    make_flo_initial_contexts(flo),
                    flo.entry_point);
        {
            std::scoped_lock<std::mutex> add_contexts_guard(
                modify_access_contexts_mutex_);
            contexts_.emplace(flo.entry_point, std::move(flo_contexts));
        }
    });
}

void Recontex::wait_for_analysis()
{
    std::for_each(analyzing_threads_.begin(),
                  analyzing_threads_.end(),
                  [](std::thread &t) { t.join(); });
    analyzing_threads_.clear();
}

void Recontex::analyze_flo(Flo &flo,
                           FloContexts &flo_contexts,
                           Contexts contexts,
                           Address address,
                           Address end,
                           std::unordered_map<Address, size_t> visited)
{
    if (!end) {
        auto last_instr = flo.get_disassembly().rbegin();
        end = last_instr->first + last_instr->second->length;
    }
    else {
        // 2nd (or more) visit
        filter_contexts(flo_contexts, address, contexts);
        if (contexts.empty()) {
            return;
        }
    }
    // Visit visited instructions without going deeper.
    while (address && address < end && !contexts.empty()
           && visited[address] < 2) {
        visited[address]++;
#ifdef DEBUG_CONTEXT_PROPAGATION
        DWORD va = pe_.raw_to_virtual_address(address);
#endif
        auto propagation_result =
            propagate_contexts(flo, flo_contexts, address, std::move(contexts));
        contexts = std::move(propagation_result.new_contexts);
        auto const instr = propagation_result.instruction;
#ifdef DEBUG_CONTEXT_PROPAGATION
        std::clog << std::dec << std::setfill(' ') << std::setw(5)
                  << contexts.size() << "ctx ";
        if (instr) {
            Dumper dumper;
            dumper.dump_instruction(std::clog, va, *instr);
            // Read values
            for (size_t i = 0; i < instr->operand_count; i++) {
                auto const &op = instr->operands[i];
                if (!(op.actions & ZYDIS_OPERAND_ACTION_MASK_READ)) {
                    continue;
                }
                for (auto const &context : contexts) {
                    switch (op.type) {
                    case ZYDIS_OPERAND_TYPE_REGISTER:
                        if (op.visibility
                            == ZYDIS_OPERAND_VISIBILITY_EXPLICIT) {
                            dump_register_value(std::clog,
                                                dumper,
                                                reflo_,
                                                context,
                                                op.reg.value);
                        }
                        break;
                    case ZYDIS_OPERAND_TYPE_MEMORY:
                        if (op.mem.base != ZYDIS_REGISTER_NONE
                            && op.mem.base != ZYDIS_REGISTER_RIP) {
                            dump_register_value(std::clog,
                                                dumper,
                                                reflo_,
                                                context,
                                                op.mem.base);
                        }
                        if (op.mem.index != ZYDIS_REGISTER_NONE) {
                            dump_register_value(std::clog,
                                                dumper,
                                                reflo_,
                                                context,
                                                op.mem.index);
                        }
                    default: break;
                    }
                }
            }
        }
        else {
            std::clog << std::hex << std::setfill('0') << std::setw(8)
                      << pe_.raw_to_virtual_address(address) << '\n';
        }
#endif
        if (!instr || contexts.empty()) {
            break;
        }
        if (instr->mnemonic == ZYDIS_MNEMONIC_CALL) {
            Contexts next_contexts;
            update_contexts_after_unknown_call(contexts, address);
        }
        else if (Flo::is_any_jump(instr->mnemonic)) {
            bool unconditional_jump = instr->mnemonic == ZYDIS_MNEMONIC_JMP;
            auto dsts = flo.get_jump_destinations(address, *instr, contexts);
            for (auto dst : dsts) {
                // Analyze only loops (inner backward jumps)
                if (dst >= address || !flo.is_inside(dst)) {
                    continue;
                }
                analyze_flo(flo,
                            flo_contexts,
                            make_child_contexts(contexts),
                            dst,
                            address,
                            visited);
                flo.add_cycle(contexts, dst, address);
            }
            if (unconditional_jump) {
                break;
            }
        }
        else if (instr->mnemonic == ZYDIS_MNEMONIC_RET) {
            // Check if next instruction is inside,
            // if so set contexts from previous inner jump
            // with current destination, otherwise stop.
            if (!flo.is_inside(address + instr->length)) {
                break;
            }
            auto const &inner_jumps = flo.get_inner_jumps();
            auto it = inner_jumps.lower_bound(address + instr->length);
            assert(it != inner_jumps.end());
            while (it != inner_jumps.end()
                   && it->first == address + instr->length) {
                ++it;
            }
            auto const &jump = std::prev(it)->second;
            auto jump_contexts =
                utils::multimap_values(flo_contexts.equal_range(jump.src));
            contexts = make_child_contexts(jump_contexts);
            address = jump.dst;
            continue;
        }
        address += instr->length;
    }
}

void Recontex::filter_contexts(FloContexts &flo_contexts,
                               Address address,
                               Contexts &contexts)
{
    // Compare contexts with existing contexts, eliminating duplicates.
    // It should be enough to filter once per basic block.
    contexts.remove_multimap_duplicates(flo_contexts, address);
}

Recontex::PropagationResult
Recontex::propagate_contexts(Flo const &flo,
                             FloContexts &flo_contexts,
                             Address address,
                             Contexts contexts)
{
    PropagationResult result;
    result.instruction = flo.get_instruction(address);
    if (!result.instruction) {
        return result;
    }
    while (!contexts.empty()) {
        auto const &context =
            emplace_context(flo_contexts, address, contexts.pop());
        auto new_context = context.make_child();
        emulate(address, *result.instruction, new_context);
        result.new_contexts.emplace(std::move(new_context));
    }
    return result;
}

Context const &Recontex::emplace_context(FloContexts &flo_contexts,
                                         Address address,
                                         Context &&context)
{
    auto range = utils::in_range(flo_contexts.equal_range(address));
    auto insert_hint = std::upper_bound(range.begin(),
                                        range.end(),
                                        context.get_hash(),
                                        [](size_t hash, auto const &it) {
                                            return hash < it.second.get_hash();
                                        });
    auto emplaced = flo_contexts.emplace_hint(insert_hint,
                                              address,
                                              std::forward<Context>(context));
    return emplaced->second;
}

void Recontex::emulate(Address address,
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
            std::bind(&Recontex::emulate_instruction_helper, _1, _2, action);
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

void Recontex::emulate_instruction(ZydisDecodedInstruction const &instruction,
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

void Recontex::emulate_instruction_lea(
    ZydisDecodedInstruction const &instruction,
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

void Recontex::emulate_instruction_push(
    ZydisDecodedInstruction const &instruction,
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

void Recontex::emulate_instruction_pop(
    ZydisDecodedInstruction const &instruction,
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

void Recontex::emulate_instruction_call(
    ZydisDecodedInstruction const &instruction,
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

void Recontex::emulate_instruction_ret(
    ZydisDecodedInstruction const &instruction,
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

void Recontex::emulate_instruction_inc(
    ZydisDecodedInstruction const &instruction,
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

virt::Value Recontex::emulate_instruction_helper(
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
        return virt::make_symbolic_value(
            src.source(),
            dst.size(),
            action(dst.symbol().offset(), src.value()),
            dst.symbol().id());
    }
    return virt::make_symbolic_value(src.source(), dst.size());
}

Recontex::Operand Recontex::get_operand(ZydisDecodedOperand const &operand,
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

std::optional<uintptr_t>
Recontex::get_memory_address(ZydisDecodedOperand const &op,
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

Contexts Recontex::make_flo_initial_contexts(Flo &flo)
{
    auto c = Context(nullptr);
    c.set_register(ZYDIS_REGISTER_RSP,
                   virt::make_value(flo.entry_point, 0xFF10000000000000));
    Contexts contexts;
    contexts.emplace(std::move(c));
    return contexts;
}

void Recontex::update_contexts_after_unknown_call(Contexts &contexts,
                                                  Address caller)
{
    Contexts new_contexts;
    std::transform(contexts.begin(),
                   contexts.end(),
                   std::inserter(new_contexts, new_contexts.end()),
                   [caller](Context const &context) {
                       auto new_context = context.make_child();
                       // Reset vlatile registers
                       for (auto volatile_register : volatile_registers_) {
                           new_context.set_register(
                               volatile_register,
                               virt::make_symbolic_value(caller));
                       }
                       return new_context;
                   });
    contexts = std::move(new_contexts);
}

bool Recontex::instruction_has_memory_access(
    ZydisDecodedInstruction const &instr)
{
    return std::any_of(instr.operands,
                       instr.operands + instr.operand_count,
                       operand_has_memory_access);
}

bool Recontex::operand_has_memory_access(ZydisDecodedOperand const &op)
{
    return op.type == ZYDIS_OPERAND_TYPE_MEMORY
           && op.visibility == ZYDIS_OPERAND_VISIBILITY_EXPLICIT;
}

bool Recontex::instruction_has_nonstack_memory_access(
    ZydisDecodedInstruction const &instr)
{
    return std::any_of(instr.operands,
                       instr.operands + instr.operand_count,
                       operand_has_nonstack_memory_access);
}

bool Recontex::operand_has_nonstack_memory_access(ZydisDecodedOperand const &op)
{
    return op.type == ZYDIS_OPERAND_TYPE_MEMORY
           && op.visibility == ZYDIS_OPERAND_VISIBILITY_EXPLICIT
           && op.mem.base != ZYDIS_REGISTER_RSP
           && op.mem.index != ZYDIS_REGISTER_RSP;
}

bool Recontex::is_history_term_instr(ZydisDecodedInstruction const &instr)
{
    if (instr.mnemonic == ZYDIS_MNEMONIC_XOR) {
        auto const &dst = instr.operands[0];
        auto const &src = instr.operands[1];
        if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER
            && src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            return dst.reg.value == src.reg.value;
        }
    }
    return false;
}

void Recontex::debug(std::ostream &os)
{
    Dumper dumper;
    for (auto const &[entry_point, flo] : reflo_.get_flos()) {
        if (get_contexts(*flo).empty()) {
            continue;
        }
        for (auto const &[address, instr] : flo->get_disassembly()) {
            if (!instruction_has_nonstack_memory_access(*instr)) {
                continue;
            }
            dump_instruction_history(os,
                                     dumper,
                                     address,
                                     *instr,
                                     get_contexts(*flo, address));
            os << "-----------------------------------------\n";
        }
    }
}

void Recontex::dump_register_history(std::ostream &os,
                                     Dumper const &dumper,
                                     Context const &context,
                                     ZydisRegister reg,
                                     std::unordered_set<Address> &visited) const
{
    {
        if (auto changed = context.get_register(reg); changed) {
            auto flo = reflo_.get_flo_by_address(changed->source());
            if (flo && !visited.contains(changed->source())) {
                visited.emplace(changed->source());
                if (!changed->is_symbolic()) {
                    os << std::hex << ' ' << std::setw(16) << changed->value()
                       << "      \t";
                }
                else {
                    os << std::hex << '[' << std::setw(8)
                       << changed->symbol().id() << '+' << std::setw(4)
                       << changed->symbol().offset() << "]\t";
                }
                dump_instruction_history(
                    os,
                    dumper,
                    changed->source(),
                    *flo->get_disassembly().at(changed->source()),
                    get_contexts(*flo, changed->source()),
                    visited);
                os << "---\n";
            }
        }
    }
}

void Recontex::dump_memory_history(std::ostream &os,
                                   Dumper const &dumper,
                                   Context const &context,
                                   ZydisDecodedOperand const &op,
                                   std::unordered_set<Address> &visited) const
{
    if (auto mem_addr = Recontex::get_memory_address(op, context); mem_addr) {
        auto values = context.get_memory(*mem_addr, op.element_size / 8);
        std::unordered_set<Address> sources;
        for (auto const &value : values.container) {
            sources.emplace(value.source());
        }
        for (auto source : sources) {
            if (visited.contains(source)) {
                continue;
            }
            if (auto flo = reflo_.get_flo_by_address(source); flo) {
                visited.emplace(source);
                dump_instruction_history(os,
                                         dumper,
                                         source,
                                         *flo->get_disassembly().at(source),
                                         get_contexts(*flo, source),
                                         visited);
            }
        }
    }
}

void Recontex::dump_instruction_history(
    std::ostream &os,
    Dumper const &dumper,
    Address address,
    ZydisDecodedInstruction const &instr,
    std::vector<Context const *> const &contexts,
    std::unordered_set<Address> visited) const
{
    visited.emplace(address);
    DWORD va = pe_.raw_to_virtual_address(address);
    dumper.dump_instruction(os, va, instr);
    if (is_history_term_instr(instr)) {
        return;
    }
    for (size_t i = 0; i < instr.operand_count; i++) {
        auto const &op = instr.operands[i];
        if (!(op.actions & ZYDIS_OPERAND_ACTION_MASK_READ)) {
            continue;
        }
        for (auto const &context : contexts) {
            switch (op.type) {
            case ZYDIS_OPERAND_TYPE_REGISTER:
                if (op.visibility == ZYDIS_OPERAND_VISIBILITY_EXPLICIT) {
                    dump_register_history(os,
                                          dumper,
                                          *context,
                                          op.reg.value,
                                          visited);
                }
                break;
            case ZYDIS_OPERAND_TYPE_MEMORY:
                if (op.mem.base != ZYDIS_REGISTER_NONE
                    && op.mem.base != ZYDIS_REGISTER_RIP) {
                    dump_register_history(os,
                                          dumper,
                                          *context,
                                          op.mem.base,
                                          visited);
                }
                if (op.mem.index != ZYDIS_REGISTER_NONE) {
                    dump_register_history(os,
                                          dumper,
                                          *context,
                                          op.mem.index,
                                          visited);
                }
                dump_memory_history(os, dumper, *context, op, visited);
                break;
            default: break;
            }
        }
    }
}
