#pragma once

#include "dumper.hxx"
#include "reflo.hxx"
#include "struc.hxx"

#include <ostream>

namespace rstc {

    class Restruc {
    public:
        Restruc(Reflo &reflo);

        void analyze();

#ifndef NDEBUG
        void debug(std::ostream &os);
        void
        dump_instruction_history(std::ostream &os,
                                 Dumper const &dumper,
                                 Address address,
                                 ZydisDecodedInstruction const &instr,
                                 std::vector<Context const *> const &contexts);
#endif

        Reflo &reflo;

    private:
        ContextPtr propagate_context(PE const &pe,
                                     Address address,
                                     ContextPtr context,
                                     std::unordered_set<Address> visited = {});
        ContextPtr make_initial_context();

        static bool
        instruction_has_memory_access(ZydisDecodedInstruction const &instr);
        static bool operand_has_memory_access(ZydisDecodedOperand const &op);

        std::vector<std::thread> analyzing_threads_;
    };

}
