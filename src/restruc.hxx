#pragma once

#include "recontex.hxx"
#include "reflo.hxx"
#include "struc.hxx"

#include <condition_variable>
#include <iosfwd>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "Zydis/Zydis.h"

namespace rstc {

    class Restruc {
    public:
        Restruc(Reflo const &reflo, Recontex const &recontex);

        void analyze();
        void set_max_analyzing_threads(size_t amount);

        void dump(std::ostream &os);

    private:
        struct InstructionsGroup {
            std::unique_ptr<Struc> struc;
            std::vector<Address> relevant_instructions;
            ZydisRegister base_root_reg;
        };
        using MemoryInstructionsGroups =
            std::map<virt::Value, InstructionsGroup>;
        using FloInstructionsGroups = std::multimap<Address, InstructionsGroup>;

        void run_analysis(Flo &flo, void (Restruc::*callback)(Flo &));
        void wait_for_analysis();

        void analyze_flo(Flo &flo);
        FloInstructionsGroups create_flo_strucs(Flo &flo,
                                    MemoryInstructionsGroups &&groups);
        void intra_link_flo_strucs(Flo &flo,
                                   Recontex::FloContexts const &flo_contexts,
                                   FloInstructionsGroups &flo_ig);
        void add_flo_strucs(Flo &flo, FloInstructionsGroups &&flo_ig);

        void inter_link_flo_strucs(Flo &flo);
        void inter_link_flo_strucs_via_register(Flo &flo,
                                                InstructionsGroup const &ig);

        std::string generate_struc_name(Flo const &flo,
                                        virt::Value const &value);
        static ZydisDecodedOperand const *
        get_memory_operand(ZydisDecodedInstruction const &instruction);
        static bool is_less_than_jump(ZydisMnemonic mnemonic);
        static size_t
        get_field_count(ZydisDecodedOperand const &mem_op,
                        std::vector<Cycle const *> const &cycles,
                        std::vector<Context const *> const &contexts);
        static void
        add_struc_field(Struc &struc,
                        std::vector<Context const *> const &contexts,
                        ZydisDecodedInstruction const &instruction,
                        std::vector<Cycle const *> const &cycles);

        Reflo const &reflo_;
        Recontex const &recontex_;
        PE const &pe_;

        std::mutex modify_access_strucs_mutex_;
        std::map<Address, FloInstructionsGroups> strucs_;

        size_t max_analyzing_threads_;
        std::atomic<size_t> analyzing_threads_count_ = 0;
        std::vector<std::thread> analyzing_threads_;
        std::mutex analyzing_threads_mutex_;
        std::condition_variable analyzing_threads_cv_;
    };

}
