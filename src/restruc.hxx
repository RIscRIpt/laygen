#pragma once

#include "reflo.hxx"
#include "struc.hxx"

#include <ostream>

namespace rstc {

    class Restruc {
    public:
#ifndef NDEBUG
        void debug(std::ostream &os, Reflo const &reflo);
#endif

    private:
        static bool instruction_has_memory_access(Instruction const &instr);
        static bool operand_has_memory_access(ZydisDecodedOperand const &op);
    };

}
