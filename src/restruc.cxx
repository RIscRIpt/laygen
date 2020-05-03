#include "restruc.hxx"

#include "dumper.hxx"

#include <algorithm>
#include <iterator>
#include <iostream>

using namespace rstc;

#define DEBUG_CONTEXT_PROPAGATION

Restruc::Restruc(Reflo &reflo)
    : reflo_(reflo)
    , pe_(reflo.get_pe())
{
}

void Restruc::analyze()
{
    if (auto ep = reflo_.get_entry_flo(); ep) {
        propagate_contexts(ep->entry_point, make_initial_contexts());
    }
}

Contexts
Restruc::propagate_contexts(Address address,
                            Contexts contexts,
                            std::unordered_multiset<Address> visited)
{
    Flo *flo = reflo_.get_flo_by_address(address);
    if (!flo) {
        return contexts;
    }
    Contexts return_contexts;
    bool new_basic_block = true;
    // Visit visited instructions without going deeper.
    while (address && !contexts.empty() && visited.count(address) < 2) {
        if (new_basic_block) {
            new_basic_block = false;
            flo->filter_contexts(address, contexts);
            if (contexts.empty()) {
                break;
            }
            flatten_contexts(contexts);
        }
        visited.emplace(address);
        auto propagation_result =
            flo->propagate_contexts(address, std::move(contexts));
        contexts = std::move(propagation_result.new_contexts);
        auto const instr = propagation_result.instruction;
#ifdef DEBUG_CONTEXT_PROPAGATION
        std::clog << std::dec << std::setfill(' ') << std::setw(8)
                  << visited.count(address) << '/' << std::setw(8)
                  << contexts.size() << ' ';
        if (instr) {
            Dumper dumper;
            dumper.dump_instruction(std::clog,
                                    pe_.raw_to_virtual_address(address),
                                    *instr);
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
                auto child_contexts = make_child_contexts(contexts);
                next_contexts =
                    propagate_contexts(dst, std::move(child_contexts), visited);
            }
            if (next_contexts.empty()) {
                set_contexts_return_value(contexts, address);
            }
            else {
                contexts = std::move(next_contexts);
            }
        }
        else if (auto unconditional_jump =
                     instr->mnemonic == ZYDIS_MNEMONIC_JMP;
                 unconditional_jump
                 || Flo::is_conditional_jump(instr->mnemonic)) {
            auto dsts =
                flo->get_jump_destinations(pe_, address, *instr, contexts);
            for (auto dst : dsts) {
                auto child_contexts = make_child_contexts(contexts);
                auto next_contexts =
                    propagate_contexts(dst, std::move(child_contexts), visited);
                if (unconditional_jump) {
                    // TODO: check if this is correct
                    return next_contexts;
                }
                else {
                    merge_contexts(return_contexts, std::move(next_contexts));
                    new_basic_block = true;
                }
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
    c.set(ZYDIS_REGISTER_RAX, ep, pe_.raw_to_virtual_address(ep));
    c.set(ZYDIS_REGISTER_RDX, c.get(ZYDIS_REGISTER_RAX));
    c.set(ZYDIS_REGISTER_RBP, ep, 0x8000000000000000);
    c.set(ZYDIS_REGISTER_RSP, ep, 0x8000000000000000);
    c.set(ZYDIS_REGISTER_R8, c.get(ZYDIS_REGISTER_RCX));
    c.set(ZYDIS_REGISTER_R9, c.get(ZYDIS_REGISTER_RAX));
    c.set(ZYDIS_REGISTER_RFLAGS, 0x244, ep);
    Contexts contexts;
    contexts.emplace(std::move(c));
    return contexts;
}

void Restruc::flatten_contexts(Contexts &contexts)
{
    Contexts new_contexts;
    std::transform(contexts.begin(),
                   contexts.end(),
                   std::inserter(new_contexts, new_contexts.end()),
                   [](Context const &context) {
                       Context new_context(&context, true);
                       return new_context;
                   });
}

Contexts Restruc::make_child_contexts(Contexts const &parents)
{
    Contexts child_contexts;
    std::transform(
        parents.begin(),
        parents.end(),
        std::inserter(child_contexts, child_contexts.end()),
        std::bind(&Context::make_flatten_child, std::placeholders::_1));
    return child_contexts;
}

void Restruc::merge_contexts(Contexts &dst, Contexts contexts)
{
    dst.merge(std::move(contexts));
}

void Restruc::set_contexts_return_value(Contexts &contexts, Address call_instr)
{
    Contexts new_contexts;
    std::transform(contexts.begin(),
                   contexts.end(),
                   std::inserter(new_contexts, new_contexts.end()),
                   [call_instr](Context const &context) {
                       Context new_context(&context, true);
                       new_context.set(ZYDIS_REGISTER_RAX, call_instr);
                       return new_context;
                   });
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
    for (auto const &[entry_point, flo] : reflo_.get_flos()) {
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
    std::vector<Context const *> const &contexts,
    std::unordered_set<Address> visited)
{
    if (visited.contains(address)) {
        return;
    }
    visited.emplace(address);
    dumper.dump_instruction(os, pe_.raw_to_virtual_address(address), instr);
    for (auto context : contexts) {
        for (size_t i = 0; i < instr.operand_count; i++) {
            auto const &op = instr.operands[i];
            if (!(op.actions & ZYDIS_OPERAND_ACTION_MASK_READ)) {
                continue;
            }
            switch (op.type) {
            case ZYDIS_OPERAND_TYPE_REGISTER:
                if (auto changed = context->get(op.reg.value);
                    changed.source != nullptr) {
                    auto flo = reflo_.get_flo_by_address(changed.source);
                    if (flo) {
                        dump_instruction_history(
                            os,
                            dumper,
                            changed.source,
                            *flo->get_disassembly().at(changed.source),
                            flo->get_contexts(changed.source),
                            visited);
                        os << "---\n";
                    }
                }
                break;
            default: break;
            }
        }
    }
}

#endif
