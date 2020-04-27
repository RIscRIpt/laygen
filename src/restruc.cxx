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
