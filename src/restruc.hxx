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

        void debug(std::ostream &os);

    private:
        Contexts
        propagate_contexts(Address address,
                           Contexts contexts,
                           std::unordered_map<Address, size_t> visited = {});
        Contexts make_initial_contexts();

        static Contexts make_child_contexts(Contexts const &parents,
                                            Context::ParentRole parent_role);
        static void merge_contexts(Contexts &dst, Contexts contexts);
        static void update_contexts_after_unknown_call(Contexts &contexts,
                                                       Address caller);
        static void set_contexts_after_call(Contexts &contexts,
                                            Contexts const &next_contexts);
        static bool
        instruction_has_memory_access(ZydisDecodedInstruction const &instr);
        static bool operand_has_memory_access(ZydisDecodedOperand const &op);
        static bool is_history_term_instr(ZydisDecodedInstruction const &instr);

        void dump_register_history(std::ostream &os,
                                   Dumper const &dumper,
                                   Context const &context,
                                   ZydisRegister reg,
                                   std::unordered_set<Address> &visited);
        void
        dump_instruction_history(std::ostream &os,
                                 Dumper const &dumper,
                                 Address address,
                                 ZydisDecodedInstruction const &instr,
                                 std::vector<Context const *> const &contexts,
                                 std::unordered_set<Address> visited = {});

        Reflo &reflo_;
        PE const &pe_;
        std::vector<std::thread> analyzing_threads_;
    };

}
