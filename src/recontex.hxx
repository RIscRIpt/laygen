#pragma once

#include "dumper.hxx"
#include "reflo.hxx"
#include "struc.hxx"

#include <ostream>

namespace rstc {

    class Recontex {
    public:
        Recontex(Reflo &reflo);

        void analyze();
        void set_max_analyzing_threads(size_t amount);

        void debug(std::ostream &os);

    private:
        void run_analysis(Flo &flo);
        void wait_for_analysis();

        void
        propagate_contexts(Flo &flo,
                           Contexts contexts,
                           Address address,
                           Address end = nullptr,
                           std::unordered_map<Address, size_t> visited = {});

        Contexts make_flo_initial_contexts(Flo &flo);

        template<typename CS>
        static Contexts make_child_contexts(CS const &parents)
        {
            Contexts child_contexts;
            std::transform(
                parents.begin(),
                parents.end(),
                std::inserter(child_contexts, child_contexts.end()),
                std::bind(&Context::make_child, std::placeholders::_1));
            return child_contexts;
        }

        static void update_contexts_after_unknown_call(Contexts &contexts,
                                                       Address caller);
        static bool
        instruction_has_memory_access(ZydisDecodedInstruction const &instr);
        static bool operand_has_memory_access(ZydisDecodedOperand const &op);
        static bool instruction_has_nonstack_memory_access(
            ZydisDecodedInstruction const &instr);
        static bool
        operand_has_nonstack_memory_access(ZydisDecodedOperand const &op);
        static bool is_history_term_instr(ZydisDecodedInstruction const &instr);

        void dump_register_history(std::ostream &os,
                                   Dumper const &dumper,
                                   Context const &context,
                                   ZydisRegister reg,
                                   std::unordered_set<Address> &visited) const;
        void dump_memory_history(std::ostream &os,
                                 Dumper const &dumper,
                                 Context const &context,
                                 ZydisDecodedOperand const &op,
                                 std::unordered_set<Address> &visited) const;
        void dump_instruction_history(
            std::ostream &os,
            Dumper const &dumper,
            Address address,
            ZydisDecodedInstruction const &instr,
            std::vector<Context const *> const &contexts,
            std::unordered_set<Address> visited = {}) const;

        Reflo &reflo_;
        PE const &pe_;

        size_t max_analyzing_threads_;
        std::atomic<size_t> analyzing_threads_count_ = 0;
        std::vector<std::thread> analyzing_threads_;
        std::mutex analyzing_threads_mutex_;
        std::condition_variable analyzing_threads_cv_;
    };

}
