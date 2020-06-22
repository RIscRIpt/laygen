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
        struct StrucWrapper {
            std::unique_ptr<Struc> struc;
            std::map<Address, ZydisDecodedInstruction const *>
                relevant_instructions;
            ZydisRegister base_reg;
        };

        using FloStrucs = std::multimap<Address, StrucWrapper>;

        struct FloInfo {
            FloStrucs strucs;
            std::map<Address, ZydisRegister> base_map;
            std::map<virt::Value, ZydisRegister> root_map;

            inline bool empty() const
            {
                return strucs.empty() && base_map.empty() && root_map.empty();
            }
        };

        Restruc(Reflo const &reflo, Recontex const &recontex);

        void analyze();
        void set_max_analyzing_threads(size_t amount);

        void dump(std::ostream &os);

    private:
        using VirtValueGroups = std::map<virt::Value, StrucWrapper>;

        FloInfo *get_flo_info(Flo const &flo);

        void run_analysis(Flo &flo, void (Restruc::*callback)(Flo &));
        void wait_for_analysis();

        void analyze_flo(Flo &flo);
        void create_flo_strucs(Flo &flo,
                               FloInfo &flo_info,
                               VirtValueGroups &&groups);
        void intra_link_flo_strucs(Flo &flo,
                                   Recontex::FloContexts const &flo_contexts,
                                   FloInfo &flo_ig);
        void add_flo_info(Flo &flo, FloInfo &&flo_ig);

        void inter_link_flo_strucs(Flo &flo);
        void inter_link_flo_strucs_via_stack(Flo const &flo,
                                             StrucWrapper const &sw,
                                             unsigned argument);
        void inter_link_flo_strucs_via_register(Flo const &flo,
                                                StrucWrapper const &sw);
        Address find_ref_sw_base(virt::Value const &value,
                                 FloInfo const &ref_flo_info);
        ZydisRegister find_ref_sw_base_reg(Address ref_sw_base,
                                           FloInfo const &ref_flo_info);
        void inter_link_flo_strucs(Flo const &flo,
                                   StrucWrapper const &sw,
                                   Flo const &ref_flo,
                                   Address ref_sw_base);

        void merge_strucs(Struc &dst, Struc const &src);

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

        std::mutex modify_access_infos_mutex_;
        std::map<Address, FloInfo> infos_;

        size_t max_analyzing_threads_;
        std::atomic<size_t> analyzing_threads_count_ = 0;
        std::vector<std::thread> analyzing_threads_;
        std::mutex analyzing_threads_mutex_;
        std::condition_variable analyzing_threads_cv_;
    };

}
