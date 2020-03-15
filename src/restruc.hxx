#pragma once

#include "pe.hxx"

#include <Zydis/Zydis.h>

#include <deque>
#include <map>
#include <set>

namespace rstc {

    using Address = BYTE *;

    class Restruc {
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
        using Jumps = std::multimap<Address, Jump>;

        struct Call : public Jump {
            Call(Address dst, Address src, Address ret)
                : Jump(Jump::Outer, dst, src)
                , ret(ret)
            {
            }
            Address const ret;
        };
        using Calls = std::multimap<Address, Call>;

    private:
        struct Flow {
            Instructions instructions;
            Jumps inner_jumps;
            Jumps outer_jumps;
            Jumps unknown_jumps;
            Calls calls;
            bool has_ret = false;

            void merge(Flow &other);
        };

        struct CFGraph : public Flow {
            CFGraph();
            CFGraph(Address entry_point, CFGraph *outer_cfgraph = nullptr);

            Address const entry_point;
            CFGraph *const outer_cfgraph;

            bool is_complete() const;
            bool can_merge_with_outer_cfgraph() const;
            Address analyze(Address address);

            void add_instruction(Address address,
                                 ZydisDecodedInstruction const &instruction);
            void add_jump(Jump::Type type, Address dst, Address src);
            void add_call(Address dst, Address src, Address ret);

            void visit(Address address);
            bool is_inside(Address address);
            bool promote_unknown_jump(Address dst, Jump::Type new_type);
            bool promote_outer_unknown_jump(Address dst, Jump::Type new_type);
            Jump::Type get_jump_type(Address dst, Address src, Address next);
        };

    public:
        class Function : private Flow {
        public:
            Function(Instructions &&instructions);

            inline Jumps const &get_outer_jumps() const { return outer_jumps; }
        };

        Restruc(std::filesystem::path const &pe_path);

        void analyze();

#ifndef NDEBUG
        void debug(std::ostream &os);
        void dump_instruction(std::ostream &os,
                              DWORD va,
                              ZydisDecodedInstruction const &instruction);
        void dump_function(std::ostream &os,
                           ZydisFormatter const &formatter,
                           CFGraph const &function);
#endif

    private:
        void fill_cfgraph(CFGraph &cfgraph);
        void resolve_incomplete_cfgraph(CFGraph &cfgraph);
        void create_function(Address entry_point);

        Address pop_unanalyzed_function();

        ZydisDecoder decoder_;
#ifndef NDEBUG
        ZydisFormatter formatter_;
#endif

        PE pe_;

        std::map<Address, CFGraph> functions_;
        std::deque<Address> unanalyzed_functions_;
    };

    namespace impl {
        /*
        // clang-format off
        template<typename T>
        concept MultimapOfDestinations = requires
        {
            { T::value_type::first_type } -> Address;
            { T::value_type::second_type::dst } -> Address const;
            { T::value_type::second_type::src } -> Address const;
        };
        // clang-format on
        */

        template</*MultimapOfDestinations*/ typename Map>
        void merge_keeping_src_unique(Map &dst_map, Map &src_map)
        {
            for (auto const &[_, src] : src_map) {
                bool dst_map_has_src = false;
                for (auto ii = dst_map.equal_range(src.dst);
                     ii.first != ii.second;
                     ++ii.first) {
                    auto dst_src = ii.first->second.src;
                    if (dst_src == src.src) {
                        dst_map_has_src = true;
                        break;
                    }
                }
                if (!dst_map_has_src) {
                    dst_map.emplace(src.dst, src);
                }
            }
        }
    }

}
