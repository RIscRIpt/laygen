#pragma once

#include "flo.hxx"

#include <Zydis/Zydis.h>

#include <ostream>

namespace rstc {

    class Dumper {
    public:
        Dumper();

        void dump_flo(std::ostream &os, Flo const &flo, DWORD entry_point_va);
        void dump_instruction(std::ostream &os,
                              DWORD va,
                              Instruction const &instruction);

    private:
        ZydisFormatter formatter_;
    };

}
