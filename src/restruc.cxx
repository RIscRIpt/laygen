#include "restruc.hxx"

#include "dumper.hxx"

#include <algorithm>

using namespace rstc;

bool Restruc::instruction_has_memory_access(Instruction const &instr)
{
    return std::any_of(instr->operands,
                       instr->operands + instr->operand_count,
                       operand_has_memory_access);
}

bool Restruc::operand_has_memory_access(ZydisDecodedOperand const &op)
{
    return op.type == ZYDIS_OPERAND_TYPE_MEMORY
           && op.visibility == ZYDIS_OPERAND_VISIBILITY_EXPLICIT;
}

#ifndef NDEBUG


void Restruc::dump_instruction_history(std::ostream &os,
                                       Reflo const &reflo,
                                       Address address,
                                       ContextedInstruction const &ctx_instr)
{
    Dumper dumper;
    auto const &instr = ctx_instr.instruction;
    dumper.dump_instruction(os,
                            reflo.get_pe().raw_to_virtual_address(address),
                            instr);
    for (auto const &ctx : ctx_instr.contexts) {
        for (size_t i = 0; i < instr->operand_count; i++) {
            auto const &op = instr->operands[i];
            if (!(op.actions & ZYDIS_OPERAND_ACTION_MASK_READ)) {
                continue;
            }
            switch (op.type) {
            case ZYDIS_OPERAND_TYPE_REGISTER:
                if (auto changed = ctx->get(op.reg.value);
                    changed.second != nullptr) {
                    auto flo = reflo.get_flo_by_address(changed.first.source);
                    if (flo) {
                        dump_instruction_history(
                            os,
                            reflo,
                            changed.first.source,
                            flo->get_disassembly().at(changed.first.source));
                        os << "---\n";
                    }
                }
                break;
            }
        }
    }
}

void Restruc::debug(std::ostream &os, Reflo const &reflo)
{
    Dumper dumper;
    for (auto const &[entry_point, flo] : reflo.get_flos()) {
        for (auto const &[address, ctx_instr] : flo->get_disassembly()) {
            // if (instruction_has_memory_access(ctx_instr.instruction)) {
            dump_instruction_history(os, reflo, address, ctx_instr);
            os << "-----------------------------------------\n";
        }
    }
}

#endif
