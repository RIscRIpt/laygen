#pragma once

#include "dumper.hxx"
#include "reflo.hxx"
#include "struc.hxx"

#include <ostream>

namespace rstc {

    class Recontex {
    public:
        using FloContexts = std::multimap<Address, Context>;

        Recontex(Reflo &reflo);

        void analyze();
        void set_max_analyzing_threads(size_t amount);

        FloContexts const &get_contexts(Flo const &flo) const;
        std::vector<Context const *> get_contexts(Flo const &flo,
                                                  Address address) const;

        static std::optional<uintptr_t>
        get_memory_address(ZydisDecodedOperand const &op,
                           Context const &context);

        void debug(std::ostream &os);

    private:
        struct PropagationResult {
            Contexts new_contexts;
            ZydisDecodedInstruction const *instruction = nullptr;
        };

        struct Operand {
            virt::Value value = virt::Value();
            std::optional<uintptr_t> address = std::nullopt;
            ZydisRegister reg = ZYDIS_REGISTER_NONE;
        };

        using EmulationCallback =
            std::function<virt::Value(virt::Value const &dst,
                                      virt::Value const &src)>;
        using EmulationCallbackAction =
            std::function<uintptr_t(uintptr_t, uintptr_t)>;

        void run_analysis(Flo &flo);
        void wait_for_analysis();

        void analyze_flo(Flo &flo,
                         FloContexts &flo_contexts,
                         Contexts contexts,
                         Address address,
                         Address end = nullptr,
                         std::unordered_map<Address, size_t> visited = {});

        void filter_contexts(FloContexts &flo_contexts,
                             Address address,
                             Contexts &contexts);
        PropagationResult propagate_contexts(Flo const &flo,
                                             FloContexts &flo_contexts,
                                             Address address,
                                             Contexts contexts);
        Context const &emplace_context(FloContexts &flo_contexts,
                                       Address address,
                                       Context &&context);
        void emulate(Address address,
                     ZydisDecodedInstruction const &instruction,
                     Context &context);
        void emulate_instruction(ZydisDecodedInstruction const &instruction,
                                 Context &context,
                                 Address address,
                                 EmulationCallback const &callback);
        void emulate_instruction_lea(ZydisDecodedInstruction const &instruction,
                                     Context &context,
                                     Address address);
        void
        emulate_instruction_push(ZydisDecodedInstruction const &instruction,
                                 Context &context,
                                 Address address);
        void emulate_instruction_pop(ZydisDecodedInstruction const &instruction,
                                     Context &context,
                                     Address address);
        void
        emulate_instruction_call(ZydisDecodedInstruction const &instruction,
                                 Context &context,
                                 Address address);
        void emulate_instruction_ret(ZydisDecodedInstruction const &instruction,
                                     Context &context,
                                     Address address);
        void emulate_instruction_inc(ZydisDecodedInstruction const &instruction,
                                     Context &context,
                                     Address address,
                                     int offset);
        static virt::Value emulate_instruction_helper(
            virt::Value const &dst,
            virt::Value const &src,
            std::function<uintptr_t(uintptr_t, uintptr_t)> action);
        static Operand get_operand(ZydisDecodedOperand const &operand,
                                   Context const &context,
                                   Address source);

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

        std::mutex modify_access_contexts_mutex_;
        std::map<Address, FloContexts> contexts_;

        size_t max_analyzing_threads_;
        std::atomic<size_t> analyzing_threads_count_ = 0;
        std::vector<std::thread> analyzing_threads_;
        std::mutex analyzing_threads_mutex_;
        std::condition_variable analyzing_threads_cv_;

        static ZydisRegister const nonvolatile_registers_[];
        static ZydisRegister const volatile_registers_[];
        static std::unordered_map<ZydisMnemonic, EmulationCallbackAction>
            emulation_callback_actions_;
    };

}
