#pragma once

#include "pe.hxx"

#include <Zydis/Zydis.h>

#include <atomic>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <thread>

namespace rstc {

    using Address = BYTE *;

    class Reflo {
    public:
        using Instructions = std::map<Address, ZydisDecodedInstruction>;

        struct Jump {
            enum Type {
                Unknown,
                Inner,
                Outer,
            };
            Jump(Type type, Address dst, Address src)
                : type(type)
                , dst(dst)
                , src(src)
            {
            }
            Type const type;
            Address const dst;
            Address const src;
        };

        // Destination -> Jump
        using Jumps = std::multimap<Address, Jump>;

        struct Call : public Jump {
            Call(Address dst, Address src, Address ret)
                : Jump(Jump::Outer, dst, src)
                , ret(ret)
            {
            }
            Address const ret;
        };

        // Destination -> Call
        using Calls = std::multimap<Address, Call>;

    private:
        struct CFGraph {
            Address const entry_point;
            Instructions instructions;
            Jumps inner_jumps;
            Jumps outer_jumps;
            Jumps unknown_jumps;
            Calls calls;
            bool has_ret = false;
            int stack_depth = 0;
            bool stack_was_modified = false;

            enum AnalysisStatus {
                Next,
                UnknownJump,
                InnerJump,
                OuterJump,
                Complete,
            };

            enum SPManipulationType {
                SPModified,
                SPUnmodified,
                SPAmbiguous,
            };

            struct AnalysisResult {
                AnalysisStatus const status;
                Address const next_address;
            };

            CFGraph();
            CFGraph(Address entry_point);

            bool is_complete() const;
            bool is_jump_table_entry() const;
            AnalysisResult analyze(PE &pe, Address address);
            SPManipulationType analyze_stack_pointer_manipulation(
                ZydisDecodedInstruction const &instruction);
            Address get_unanalized_inner_jump_dst() const;

            static bool is_conditional_jump(ZydisMnemonic mnemonic);

            void add_instruction(Address address,
                                 ZydisDecodedInstruction const &instruction);
            void add_jump(Jump::Type type, Address dst, Address src);
            void add_call(Address dst, Address src, Address ret);

            void visit(Address address);
            bool is_inside(Address address) const;
            bool promote_unknown_jump(Address dst, Jump::Type new_type);
            Jump::Type
            get_jump_type(Address dst, Address src, Address next) const;
            bool stack_depth_is_ambiguous() const;
        };

    public:
        Reflo(std::filesystem::path const &pe_path);

        void analyze();
        void set_max_analyzing_threads(size_t amount);

#ifndef NDEBUG
        void debug(std::ostream &os);
        void dump_instruction(std::ostream &os,
                              DWORD va,
                              ZydisDecodedInstruction const &instruction);
        void dump_cfgraph(std::ostream &os,
                          ZydisFormatter const &formatter,
                          CFGraph const &cfgraph);
#endif

    private:
        ZydisDecodedInstruction decode_instruction(Address address,
                                                   Address end);

        void fill_cfgraph(CFGraph &cfgraph);
        void post_fill_cfgraph(CFGraph &cfgraph);
        void analyze_cfgraph(Address entry_point);
        void post_analyze_cfgraph(CFGraph &cfgraph);
        void find_and_analyze_cfgraphs();
        void promote_jumps_to_outer();
        void promote_jumps_to_inner();
        void post_analyze_cfgraphs();
        void wait_for_all_analyzing_threads();
        bool unknown_jumps_exist() const;

        Address pop_unprocessed_cfgraph();

        ZydisDecoder decoder_;
#ifndef NDEBUG
        ZydisFormatter formatter_;
#endif

        PE pe_;

        size_t max_analyzing_threads_;
        std::atomic<size_t> analyzing_threads_count_ = 0;
        std::mutex creating_cfgraph_mutex_;
        std::mutex cfgraphs_mutex_;
        std::condition_variable cfgraphs_cv_;
        std::vector<std::thread> analyzing_threads_;
        std::set<Address> created_cfgraphs_;
        std::map<Address, std::unique_ptr<CFGraph>> cfgraphs_;
        std::deque<Address> unprocessed_cfgraphs_;
    };

}
