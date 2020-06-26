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
        struct StrucDomain {
            std::shared_ptr<Struc> struc;
            Flo const *base_flo;
            std::map<Address, ZydisDecodedInstruction const *>
                relevant_instructions;
            std::unordered_multimap<Address, ZydisRegister> base_regs;
        };

        struct FloDomain {
            std::unordered_map<virt::Value, StrucDomain> strucs;
            std::unordered_map<virt::Value, ZydisRegister> root_map;
            std::unordered_map<Address, ZydisRegister> base_map;

            inline bool empty() const
            {
                return strucs.empty() && base_map.empty() && root_map.empty();
            }
        };

        Restruc(Reflo const &reflo, Recontex const &recontex);

        void analyze();
        void set_max_analyzing_threads(size_t amount);

        void dump(std::ostream &os);

        inline std::map<std::string, std::shared_ptr<Struc>> const &
        get_strucs() const
        {
            return strucs_;
        }

    private:
        using ValueGroups = std::map<virt::Value, StrucDomain>;
        struct StrucDomainBase {
            Address source;
            ZydisRegister root_reg;
        };

        FloDomain *get_flo_domain(Flo const &flo);

        void run_analysis(Flo &flo, void (Restruc::*callback)(Flo &));
        void wait_for_analysis();

        void analyze_flo(Flo &flo);
        void
        create_flo_strucs(Flo &flo, FloDomain &flo_info, ValueGroups &&groups);
        void intra_link_flo_strucs(Flo &flo,
                                   Recontex::FloContexts const &flo_contexts,
                                   FloDomain &flo_ig);
        void add_flo_domain(Flo &flo, FloDomain &&flo_ig);

        void inter_link_flo_strucs(Flo &flo);
        void
        inter_link_flo_strucs_via_stack(Flo const &flo,
                                        StrucDomain const &sd,
                                        unsigned argument,
                                        std::unordered_set<Address> &visited);
        void inter_link_flo_strucs_via_register(
            Flo const &flo,
            StrucDomain const &sd,
            ZydisRegister base_reg,
            std::unordered_set<Address> &visited);
        std::optional<StrucDomainBase>
        find_ref_sd_base(virt::Value const &value,
                         FloDomain const &ref_flo_info);
        ZydisRegister find_ref_sd_base_reg(Address ref_sd_base,
                                           FloDomain const &ref_flo_info);
        void inter_link_flo_strucs(Flo const &flo,
                                   StrucDomain const &sd,
                                   Flo const &ref_flo,
                                   Address ref_sd_base);

        void merge_strucs(Struc &dst, Struc const &src);

        std::string generate_struc_name(Flo const &flo,
                                        virt::Value const &value);
        static ZydisDecodedOperand const *
        get_memory_operand(ZydisDecodedInstruction const &instruction);
        static bool is_less_than_jump(ZydisMnemonic mnemonic);
        size_t get_field_count(ZydisDecodedOperand const &mem_op,
                               std::vector<Cycle const *> const &cycles,
                               Address address,
                               Recontex::FloContexts const &contexts);
        void add_struc_field(Struc &struc,
                             Address address,
                             Recontex::FloContexts const &contexts,
                             ZydisDecodedInstruction const &instruction,
                             std::vector<Cycle const *> const &cycles);

        Reflo const &reflo_;
        Recontex const &recontex_;
        PE const &pe_;

        std::mutex modify_access_domains_mutex_;
        std::mutex modify_access_strucs_mutex_;
        std::map<Address, FloDomain> domains_;
        std::map<std::string, std::shared_ptr<Struc>> strucs_;

        size_t max_analyzing_threads_;
        std::atomic<size_t> analyzing_threads_count_ = 0;
        std::vector<std::thread> analyzing_threads_;
        std::mutex analyzing_threads_mutex_;
        std::condition_variable analyzing_threads_cv_;
    };

}
