#pragma once

#include "dumper.hxx"
#include "reflo.hxx"
#include "struc.hxx"

#include "utils/hash.hxx"

#include <list>
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

        static virt::Value get_memory_address(ZydisDecodedOperand const &op,
                                              Context const &context);

        static bool points_to_stack(ZydisRegister reg,
                                    Address address,
                                    FloContexts const &flo_contexts);
        static bool points_to_stack(uintptr_t value);
        static unsigned stack_argument_number(uintptr_t value);

        void debug(std::ostream &os);

    private:
        class OptimalCoverage {
        public:
            struct Edge {
                Edge(Address src, Address dst)
                    : src(src)
                    , dst(dst)
                {
                }
                bool operator==(Edge const &other) const
                {
                    return src == other.src && dst == other.dst;
                }
                Address src, dst;
            };

            struct EdgeHash {
                std::size_t operator()(Edge const &e) const
                {
                    std::size_t h = 0;
                    utils::hash::combine(h, e.src);
                    utils::hash::combine(h, e.dst);
                    return h;
                }
            };

            using Edges = std::unordered_set<Edge, EdgeHash>;

            struct Branch {
                enum Type {
                    Conditional,
                    Unconditional,
                    Next,
                };
                Branch(Address source, Address branch, Type type)
                    : source(source)
                    , branch(branch)
                    , type(type)
                {
                }
                Address source;
                Address branch;
                Type type;
            };

            struct Node {
                Node(Address source, std::list<Branch> branches)
                    : source(source)
                    , branches(std::move(branches))
                {
                }
                Address source;
                // Branches can be:
                // (a) a single unconditional jump;
                // (b) a step `Branch::Type::Next` or unconditional jump,
                //     and a list of conditional jumps.
                std::list<Branch> branches;
            };

            struct Decision {
                Decision(Address jump, bool take)
                    : jump(jump)
                    , take(take)
                {
                }
                Address jump;
                bool take;
            };

            // Path is a set of decisions whether to jump or not at an address
            using Path = std::vector<Decision>;
            using Paths = std::vector<Path>;

            OptimalCoverage(Flo const &flo);

            bool analyze();

            inline std::map<Address, Node> const &nodes() { return nodes_; }
            inline std::map<Address, size_t> const &nodes_order()
            {
                return nodes_order_;
            }
            inline Edges const &loops() { return loops_; }
            inline Edges const &useless_edges() { return useless_edges_; }
            inline Paths const &paths() { return paths_; }

        private:
            bool build_nodes();
            bool validate_nodes();
            void normalize_nodes();
            void top_sort();
            void find_loops();
            void find_useless_edges();
            void build_paths();

            Flo const &flo_;
            std::unordered_set<Address> ends_;
            std::map<Address, Node> nodes_;
            std::map<Address, size_t> nodes_order_;
            Edges loops_;
            Edges useless_edges_;
            Paths paths_;
        };

        struct AnalyzePath {
            AnalyzePath(OptimalCoverage::Path const &path)
                : current(path.begin())
                , end(path.end())
            {
            }
            OptimalCoverage::Path::const_iterator current, end;
        };

        using AnalyzePaths = std::vector<AnalyzePath>;

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
                         AnalyzePaths paths,
                         Contexts contexts,
                         Address address);

        static AnalyzePaths
        optimal_paths_to_analyze_paths(OptimalCoverage::Paths const &paths);
        static AnalyzePaths split_analyze_paths(AnalyzePaths &paths);
        static void advance_analyze_paths(AnalyzePaths &paths);
        static bool same_analyze_path(AnalyzePaths const &paths);

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

        static uintptr_t const magic_stack_value_ = 0xFFF4B1D1;
        static uintptr_t const magic_stack_value_mask_ =
            (magic_stack_value_ & ~1) << 32;
        static ZydisRegister const nonvolatile_registers_[];
        static ZydisRegister const volatile_registers_[];
        static std::unordered_map<ZydisMnemonic, EmulationCallbackAction>
            emulation_callback_actions_;
    };

}
