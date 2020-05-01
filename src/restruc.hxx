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
                                 std::vector<Context const *> const &contexts,
                                 std::unordered_set<Address> visited = {});
#endif

    private:
        ContextPtrs
        propagate_contexts(Address address,
                           ContextPtrs contexts,
                           std::unordered_multiset<Address> visited = {});
        ContextPtrs make_initial_contexts();

        static ContextPtrs make_child_contexts(ContextPtrs const &parents);
        static void set_contexts_return_value(ContextPtrs &contexts,
                                              Address call_instr);
        static bool
        instruction_has_memory_access(ZydisDecodedInstruction const &instr);
        static bool operand_has_memory_access(ZydisDecodedOperand const &op);

        PE const &pe_;
        Reflo &reflo_;
        std::vector<std::thread> analyzing_threads_;
    };

}
