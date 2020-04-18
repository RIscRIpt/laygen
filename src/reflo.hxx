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
#include <unordered_set>

namespace rstc {

    using Address = BYTE *;
    using Instruction = std::unique_ptr<ZydisDecodedInstruction>;

    class Reflo {
    public:
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

        struct Register {
            uintptr_t value = 0;
            uintptr_t mask = 0;

            Register &operator=(Register const &other)
            {
                value = other.value;
                mask = other.mask;
                return *this;
            }

            Register &operator=(uintptr_t new_value)
            {
                value = new_value;
                mask = ~0;
                return *this;
            }

            void unset()
            {
                value = 0;
                mask = 0;
            }

            Register &operator+=(uintptr_t value)
            {
                value += value;
                value &= mask;
                return *this;
            }

            Register &operator-=(uintptr_t value)
            {
                value -= value;
                value &= mask;
                return *this;
            }
        };

        struct Context {
            Register rax, rbx, rcx, rdx, rsp, rbp, rsi, rdi;
            Register r8, r9, r10, r11, r12, r13, r14, r15;
            Register rflags;
        };

        using ContextPtr = std::unique_ptr<Context>;

        struct ContextedInstruction {
            Instruction instruction;
            ContextPtr context;
        };

        using Disassembly = std::map<Address, ContextedInstruction>;

    private:
        class CFGraph {
        public:
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

            CFGraph(Address entry_point = nullptr,
                    ContextPtr context = nullptr);

            ContextPtr get_context(Address address) const;
            AnalysisResult analyze(Address address, Instruction instr);
            SPManipulationType analyze_stack_pointer_manipulation(
                ZydisDecodedInstruction const &instruction);
            Address get_unanalized_inner_jump_dst() const;

            void add_jump(Jump::Type type, Address dst, Address src);
            void add_call(Address dst, Address src, Address ret);

            bool stack_depth_is_ambiguous() const;

            Address const entry_point;
            Disassembly disassembly;
            Jumps inner_jumps;
            Jumps outer_jumps;
            Jumps unknown_jumps;
            Calls calls;
            bool has_ret = false;
            int stack_depth = 0;
            bool stack_was_modified = false;

        private:
            bool is_inside(Address address) const;
            Jump::Type
            get_jump_type(Address dst, Address src, Address next) const;

            void emulate(ZydisDecodedInstruction const &instruction,
                         Context &context) const;
            void visit(Address address);
            bool promote_unknown_jump(Address dst, Jump::Type new_type);

            static bool is_conditional_jump(ZydisMnemonic mnemonic);

            // Will be nullptr after first instruction is added to disassembly
            ContextPtr mutable initial_context;
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
        Instruction decode_instruction(Address address, Address end);

        void fill_cfgraph(CFGraph &cfgraph);
        void post_fill_cfgraph(CFGraph &cfgraph);
        void wait_before_analysis_run();
        void run_cfgraph_analysis(Address entry_point, ContextPtr context);
        void run_cfgraph_post_analysis(CFGraph &cfgraph);
        void find_and_analyze_cfgraphs();
        void promote_jumps_to_outer();
        void promote_jumps_to_inner();
        void post_analyze_cfgraphs();
        void wait_for_analysis();
        bool unknown_jumps_exist() const;

        Address pop_unprocessed_cfgraph();

        ContextPtr make_initial_context();
        ContextPtr make_cfgraph_initial_context(Context const &src_context);

        ZydisDecoder decoder_;
#ifndef NDEBUG
        ZydisFormatter formatter_;
#endif

        PE pe_;

        size_t max_analyzing_threads_;
        std::atomic<size_t> analyzing_threads_count_ = 0;
        std::mutex cfgraphs_mutex_;
        std::condition_variable cfgraphs_cv_;
        std::vector<std::thread> analyzing_threads_;
        std::unordered_set<Address> created_cfgraphs_;
        std::map<Address, std::unique_ptr<CFGraph>> cfgraphs_;
        std::deque<Address> unprocessed_cfgraphs_;
    };

}
