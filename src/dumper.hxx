#pragma once

#include "flo.hxx"
#include "virtual/value.hxx"

#include <Zydis/Zydis.h>

#include <ostream>

namespace rstc {

    class Dumper {
    public:
        Dumper();

        void
        dump_flo(std::ostream &os, Flo const &flo, DWORD entry_point_va) const;
        void dump_instruction(std::ostream &os,
                              DWORD va,
                              ZydisDecodedInstruction const &instruction) const;
        void dump_value(std::ostream &os, virt::Value const &value) const;

    private:
        ZydisFormatter formatter_;
    };

}
