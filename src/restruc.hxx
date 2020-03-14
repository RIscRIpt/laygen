#pragma once

#include "pe.hxx"

#include <Zydis/Zydis.h>

#include <deque>
#include <map>
#include <set>

namespace rstc {

    class Restruc {
    public:
        using Address = BYTE *;

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

        struct Call : public Jump {
            Call(Address dst, Address src, Address ret)
                : Jump(Jump::Outer, dst, src)
                , ret(ret)
            {
            }
            Address const ret;
        };

        class Function {
        public:
            using Instructions = std::map<Address, ZydisDecodedInstruction>;

            Function();
            Function(ZydisDecoder const &decoder,
                     Address entry_point,
                     Address end);

            Address const entry_point;

            inline const Instructions get_instructions() const
            {
                return instructions_;
            }

            inline const std::map<Address, Jump> get_inner_jumps() const
            {
                return inner_jumps_;
            }
            inline const std::map<Address, Jump> get_outer_jumps() const
            {
                return outer_jumps_;
            }
            inline const std::map<Address, Call> get_calls() const
            {
                return calls_;
            }

            bool is_inside_function(Address address);

        private:
            void promote_unknown_to_inner_jump(Address dst);
            void visit(Address address);

            Jump::Type
            get_jump_type(Address dst, Address src, Address next_address);

            void add_jump(Jump::Type type, Address dst, Address src);
            void add_call(Address dst, Address src, Address ret);

            Instructions instructions_;
            std::map<Address, Jump> inner_jumps_;
            std::map<Address, Jump> outer_jumps_;
            std::map<Address, Jump> unknown_jumps_;
            std::map<Address, Call> calls_;
            std::set<Address> unvisited_;
        };

        Restruc(std::filesystem::path const &pe_path);

        void analyze();

    private:
        void
        add_function(ZydisDecoder const &decoder, Address address, Address end);

        Address pop_unanalyzed_function();

        PE pe_;

        std::map<Address, Function> functions_;
        std::deque<Address> unanalyzed_functions_;
    };

}
