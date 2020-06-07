#pragma once

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
        Restruc(Reflo &reflo);

        void analyze();
        void set_max_analyzing_threads(size_t amount);

        void dump(std::ostream &os);

    private:
        using MemoryInstructionGroups =
            std::map<virt::Value, std::vector<Address>>;
        using FloStrucs = std::multimap<Address, std::unique_ptr<Struc>>;

        void run_analysis(Flo &flo);
        void wait_for_analysis();

        void analyze_flo(Flo &flo);
        FloStrucs create_flo_strucs(Flo &flo,
                                    MemoryInstructionGroups const &groups);
        void link_flo_strucs(Flo &flo, FloStrucs &flo_strucs);
        void add_flo_strucs(Flo &flo, FloStrucs &&flo_strucs);

        Struc &make_struc(Flo &flo, FloStrucs &flo_strucs, virt::Value value);
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
        Reflo &reflo_;
        PE const &pe_;

        std::mutex modify_access_strucs_mutex_;
        std::map<Address, FloStrucs> strucs_;

        size_t max_analyzing_threads_;
        std::atomic<size_t> analyzing_threads_count_ = 0;
        std::vector<std::thread> analyzing_threads_;
        std::mutex analyzing_threads_mutex_;
        std::condition_variable analyzing_threads_cv_;
    };

}
