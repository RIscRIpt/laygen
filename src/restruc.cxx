#include "restruc.hxx"

#include "dumper.hxx"

#include <algorithm>
#include <iostream>
#include <iterator>

using namespace rstc;

#define DEBUG_CONTEXT_PROPAGATION

static ZydisRegister const VOLATILE_REGISTERS[] = {
    ZYDIS_REGISTER_RAX,  ZYDIS_REGISTER_RCX,  ZYDIS_REGISTER_RDX,
    ZYDIS_REGISTER_R8,   ZYDIS_REGISTER_R9,   ZYDIS_REGISTER_R10,
    ZYDIS_REGISTER_R11,  ZYDIS_REGISTER_ZMM0, ZYDIS_REGISTER_ZMM1,
    ZYDIS_REGISTER_ZMM2, ZYDIS_REGISTER_ZMM3, ZYDIS_REGISTER_ZMM4,
    ZYDIS_REGISTER_ZMM5,
};

static ZydisRegister const NONVOLATILE_REGISTERS[] = {
    ZYDIS_REGISTER_RBX,   ZYDIS_REGISTER_RBP,   ZYDIS_REGISTER_RSP,
    ZYDIS_REGISTER_RDI,   ZYDIS_REGISTER_RSI,   ZYDIS_REGISTER_R12,
    ZYDIS_REGISTER_R13,   ZYDIS_REGISTER_R14,   ZYDIS_REGISTER_R15,
    ZYDIS_REGISTER_ZMM6,  ZYDIS_REGISTER_ZMM7,  ZYDIS_REGISTER_ZMM8,
    ZYDIS_REGISTER_ZMM9,  ZYDIS_REGISTER_ZMM10, ZYDIS_REGISTER_ZMM11,
    ZYDIS_REGISTER_ZMM12, ZYDIS_REGISTER_ZMM13, ZYDIS_REGISTER_ZMM14,
    ZYDIS_REGISTER_ZMM15,
};

#ifdef DEBUG_CONTEXT_PROPAGATION

void dump_register_value(std::ostream &os,
                         Dumper const &dumper,
                         Reflo &reflo,
                         Context const &context,
                         ZydisRegister reg)
{
    if (auto changed = context.get_register(reg); changed) {
        auto flo = reflo.get_flo_by_address(changed->source);
        if (flo) {
            if (changed->value) {
                os << std::setfill('0') << std::hex << std::setw(16)
                   << *changed->value << '\t';
            }
        }
    }
}

#endif

Restruc::Restruc(Reflo &reflo)
    : reflo_(reflo)
    , pe_(reflo.get_pe())
{
}

void Restruc::analyze()
{
    if (auto ef = reflo_.get_entry_flo(); ef) {
        propagate_contexts(ef->entry_point, make_initial_contexts());
    }
}

Contexts Restruc::propagate_contexts(Address address,
                                     Contexts contexts,
                                     std::unordered_map<Address, size_t> visited)
{
    Flo *flo = reflo_.get_flo_by_address(address);
    if (!flo) {
        return contexts;
    }
    Contexts return_contexts;
    bool new_basic_block = true;
    // Visit visited instructions without going deeper.
    while (address && !contexts.empty() && visited[address] < 2) {
#ifdef DEBUG_CONTEXT_PROPAGATION
        DWORD va = pe_.raw_to_virtual_address(address);
#endif
        if (new_basic_block) {
            new_basic_block = false;
            flo->filter_contexts(address, contexts);
            if (contexts.empty()) {
                break;
            }
        }
        visited[address]++;
        auto propagation_result =
            flo->propagate_contexts(address, std::move(contexts));
        contexts = std::move(propagation_result.new_contexts);
        auto const instr = propagation_result.instruction;
#ifdef DEBUG_CONTEXT_PROPAGATION
        std::clog << std::dec << std::setfill(' ') << std::setw(8)
                  << visited[address] << '/' << std::setw(8)
                  << contexts.size() << ' ';
        if (instr) {
            Dumper dumper;
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
            dumper.dump_instruction(std::clog, va, *instr);
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
            if (auto dst = flo->get_call_destination(address, *instr); dst) {
                auto child_contexts =
                    make_child_contexts(contexts, Context::ParentRole::Caller);
                next_contexts =
                    propagate_contexts(dst, std::move(child_contexts), visited);
            }
            if (next_contexts.empty()) {
                update_contexts_after_unknown_call(contexts, address);
            }
            else {
                set_contexts_after_call(contexts, next_contexts);
            }
        }
        else if (auto unconditional_jump =
                     instr->mnemonic == ZYDIS_MNEMONIC_JMP;
                 unconditional_jump
                 || Flo::is_conditional_jump(instr->mnemonic)) {
            auto dsts =
                flo->get_jump_destinations(pe_, address, *instr, contexts);
            for (auto dst : dsts) {
                auto child_contexts =
                    make_child_contexts(contexts, Context::ParentRole::Default);
                auto next_contexts =
                    propagate_contexts(dst, std::move(child_contexts), visited);
                merge_contexts(return_contexts, std::move(next_contexts));
            }
            if (unconditional_jump) {
                break;
            }
            else {
                new_basic_block = true;
            }
            if (dsts.empty() && unconditional_jump) {
                break;
            }
        }
        else if (instr->mnemonic == ZYDIS_MNEMONIC_RET) {
            merge_contexts(return_contexts, std::move(contexts));
            break;
        }
        address += instr->length;
    }
    return return_contexts;
}

Contexts Restruc::make_initial_contexts()
{
    auto ep = reflo_.get_pe().get_entry_point();
    auto c = Context(ep);
    c.set_register(ZYDIS_REGISTER_RAX, ep, pe_.raw_to_virtual_address(ep));
    c.set_register(ZYDIS_REGISTER_RDX, *c.get_register(ZYDIS_REGISTER_RAX));
    c.set_register(ZYDIS_REGISTER_RSP, ep, 0xFF10000000000000);
    c.set_register(ZYDIS_REGISTER_R8, *c.get_register(ZYDIS_REGISTER_RCX));
    c.set_register(ZYDIS_REGISTER_R9, *c.get_register(ZYDIS_REGISTER_RAX));
    c.set_register(ZYDIS_REGISTER_RFLAGS, ep, 0x244);
    Contexts contexts;
    contexts.emplace(std::move(c));
    return contexts;
}

Contexts Restruc::make_child_contexts(Contexts const &parents,
                                      Context::ParentRole parent_role)
{
    Contexts child_contexts;
    std::transform(
        parents.begin(),
        parents.end(),
        std::inserter(child_contexts, child_contexts.end()),
        std::bind(&Context::make_child, std::placeholders::_1, parent_role));
    return child_contexts;
}

void Restruc::merge_contexts(Contexts &dst, Contexts contexts)
{
    dst.merge(std::move(contexts));
}

void Restruc::update_contexts_after_unknown_call(Contexts &contexts,
                                                 Address caller)
{
    Contexts new_contexts;
    std::transform(contexts.begin(),
                   contexts.end(),
                   std::inserter(new_contexts, new_contexts.end()),
                   [caller](Context const &context) {
                       auto new_context =
                           context.make_child(Context::ParentRole::Default);
                       // Reset vlatile registers
                       for (auto volatile_register : VOLATILE_REGISTERS) {
                           new_context.set_register(volatile_register, caller);
                       }
                       return new_context;
                   });
    contexts = std::move(new_contexts);
}

void rstc::Restruc::set_contexts_after_call(Contexts &contexts,
                                            Contexts const &next_contexts)
{
    // Revert non-volatile registers
    Contexts reverted_contexts;
    std::transform(
        next_contexts.begin(),
        next_contexts.end(),
        std::inserter(reverted_contexts, reverted_contexts.end()),
        [&contexts](Context const &context) {
            auto new_context = context.make_child(Context::ParentRole::Default);
            auto caller_context =
                contexts.get_context_by_id(context.get_caller_id());
            if (caller_context) {
                for (auto nonvolatile_register : NONVOLATILE_REGISTERS) {
                    if (auto valsrc =
                            caller_context->get_register(nonvolatile_register);
                        valsrc) {
                        new_context.set_register(nonvolatile_register, *valsrc);
                    }
                }
            }
            return new_context;
        });
    contexts = std::move(reverted_contexts);
}

bool Restruc::instruction_has_memory_access(
    ZydisDecodedInstruction const &instr)
{
    return std::any_of(instr.operands,
                       instr.operands + instr.operand_count,
                       operand_has_memory_access);
}

bool Restruc::operand_has_memory_access(ZydisDecodedOperand const &op)
{
    return op.type == ZYDIS_OPERAND_TYPE_MEMORY
           && op.visibility == ZYDIS_OPERAND_VISIBILITY_EXPLICIT;
}

bool Restruc::is_history_term_instr(ZydisDecodedInstruction const &instr)
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

void Restruc::debug(std::ostream &os)
{
    Dumper dumper;
    for (auto const &[entry_point, flo] : reflo_.get_flos()) {
        if (flo->get_contexts().empty()) {
            continue;
        }
        for (auto const &[address, instr] : flo->get_disassembly()) {
            if (!instruction_has_memory_access(*instr)) {
                continue;
            }
            dump_instruction_history(os,
                                     dumper,
                                     address,
                                     *instr,
                                     flo->get_contexts(address));
            os << "-----------------------------------------\n";
        }
    }
}

void Restruc::dump_register_history(std::ostream &os,
                                    Dumper const &dumper,
                                    Context const &context,
                                    ZydisRegister reg,
                                    std::unordered_set<Address> &visited)
{
    {
        if (auto changed = context.get_register(reg); changed) {
            auto flo = reflo_.get_flo_by_address(changed->source);
            if (flo && !visited.contains(changed->source)) {
                visited.emplace(changed->source);
                if (changed->value) {
                    os << std::hex << *changed->value << '\t';
                }
                dump_instruction_history(
                    os,
                    dumper,
                    changed->source,
                    *flo->get_disassembly().at(changed->source),
                    flo->get_contexts(changed->source),
                    visited);
                os << "---\n";
            }
        }
    }
}

void Restruc::dump_instruction_history(
    std::ostream &os,
    Dumper const &dumper,
    Address address,
    ZydisDecodedInstruction const &instr,
    std::vector<Context const *> const &contexts,
    std::unordered_set<Address> visited)
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
            default: break;
            }
        }
    }
}
