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
        Contexts
        propagate_contexts(Address address,
                           Contexts contexts,
                           std::unordered_multiset<Address> visited = {});
        Contexts make_initial_contexts();

        static void flatten_contexts(Contexts &contexts);
        static Contexts make_child_contexts(Contexts const &parents);
        static void merge_contexts(Contexts &dst, Contexts contexts);
        static void set_contexts_return_value(Contexts &contexts,
                                              Address call_instr);
        static bool
        instruction_has_memory_access(ZydisDecodedInstruction const &instr);
        static bool operand_has_memory_access(ZydisDecodedOperand const &op);

        Reflo &reflo_;
        PE const &pe_;
        std::vector<std::thread> analyzing_threads_;
    };

}
