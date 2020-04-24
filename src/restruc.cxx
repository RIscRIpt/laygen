#include "restruc.hxx"

#include "dumper.hxx"

#include <algorithm>

using namespace rstc;

void Restruc::debug(std::ostream &os, Reflo const &reflo)
{
    Dumper dumper;
    for (auto const &[entry_point, flo] : reflo.get_flos()) {
        for (auto const &[address, instr] : flo->get_disassembly()) {
            if (instruction_has_memory_access(instr)) {
                dumper.dump_instruction(
                    os,
                    reflo.get_pe().raw_to_virtual_address(address),
                    instr);
            }
        }
    }
}

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
