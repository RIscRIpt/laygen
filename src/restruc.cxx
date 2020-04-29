#include "restruc.hxx"

#include "dumper.hxx"

#include <algorithm>

using namespace rstc;

Restruc::Restruc(Reflo &reflo)
    : reflo(reflo)
{
}

void Restruc::analyze()
{
    if (auto ep = reflo.get_entry_flo(); ep) {
        propagate_context(reflo.get_pe(),
                          ep->entry_point,
                          std::move(make_initial_context()));
    }
}

ContextPtr Restruc::propagate_context(PE const &pe,
                                      Address address,
                                      ContextPtr context,
                                      std::unordered_set<Address> visited)
{
    ZydisDecodedInstruction const *instr;
    Flo *flo = reflo.get_flo_by_address(address);
    if (!flo) {
        return std::move(context);
    }
    // TODO: visit despite it has already been visited, but without recursion
    while (address && context && !visited.contains(address)) {
        visited.emplace(address);
        std::tie(context, instr) =
            flo->propagate_contexts(address, std::move(context));
        if (!context || !instr) {
            break;
        }
        if (instr->mnemonic == ZYDIS_MNEMONIC_CALL) {
            if (auto dst = flo->get_call_destination(address, *instr); dst) {
                context = propagate_context(pe,
                                            dst,
                                            std::move(context->make_flatten()),
                                            visited);
            }
        }
        else if (auto unconditional_jump =
                     instr->mnemonic == ZYDIS_MNEMONIC_JMP;
                 unconditional_jump
                 || Flo::is_conditional_jump(instr->mnemonic)) {
            if (auto dst =
                    flo->get_jump_destination(pe, address, *instr, *context);
                dst) {
                auto next_context =
                    propagate_context(pe,
                                      dst,
                                      std::move(context->make_flatten()),
                                      visited);
                if (unconditional_jump) {
                    return std::move(next_context);
                }
            }
            else if (unconditional_jump) {
                break;
            }
        }
        else if (instr->mnemonic == ZYDIS_MNEMONIC_RET) {
            return std::move(context);
        }
        address += instr->length;
    }
    return nullptr;
}

ContextPtr Restruc::make_initial_context()
{
    auto ep = reflo.get_pe().get_entry_point();
    auto c = std::make_unique<Context>(ep);
    c->set(ZYDIS_REGISTER_RAX, ep, reflo.get_pe().raw_to_virtual_address(ep));
    c->set(ZYDIS_REGISTER_RDX, c->get(ZYDIS_REGISTER_RAX));
    c->set(ZYDIS_REGISTER_RBP, ep, 0x8000000000000000);
    c->set(ZYDIS_REGISTER_RSP, ep, 0x8000000000000000);
    c->set(ZYDIS_REGISTER_R8, c->get(ZYDIS_REGISTER_RCX));
    c->set(ZYDIS_REGISTER_R9, c->get(ZYDIS_REGISTER_RAX));
    c->set(ZYDIS_REGISTER_RFLAGS, 0x244, ep);
    return std::move(c);
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

#ifndef NDEBUG

void Restruc::debug(std::ostream &os)
{
    Dumper dumper;
    for (auto const &[entry_point, flo] : reflo.get_flos()) {
        if (flo->get_contexts().empty()) {
            continue;
        }
        for (auto const &[address, instr] : flo->get_disassembly()) {
            dump_instruction_history(os,
                                     dumper,
                                     address,
                                     *instr,
                                     flo->get_contexts(address));
            os << "-----------------------------------------\n";
        }
    }
}

void Restruc::dump_instruction_history(
    std::ostream &os,
    Dumper const &dumper,
    Address address,
    ZydisDecodedInstruction const &instr,
    std::vector<Context const *> const &contexts)
{
    dumper.dump_instruction(os,
                            reflo.get_pe().raw_to_virtual_address(address),
                            instr);
    for (size_t i = 0; i < instr.operand_count; i++) {
        auto const &op = instr.operands[i];
        if (!(op.actions & ZYDIS_OPERAND_ACTION_MASK_READ)) {
            continue;
        }
        for (auto context : contexts) {
            switch (op.type) {
            case ZYDIS_OPERAND_TYPE_REGISTER:
                if (auto changed = context->get(op.reg.value);
                    changed.source != nullptr) {
                    auto flo = reflo.get_flo_by_address(changed.source);
                    if (flo) {
                        dump_instruction_history(
                            os,
                            dumper,
                            changed.source,
                            *flo->get_disassembly().at(changed.source),
                            flo->get_contexts(changed.source));
                        os << "---\n";
                    }
                }
                break;
            }
        }
    }
}

#endif
