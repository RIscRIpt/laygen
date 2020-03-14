#pragma once

#include "pe.hxx"

#include <Zydis/Zydis.h>

#include <map>
#include <unordered_set>
#include <vector>

namespace rstc {

    class Restruc {
    public:
        using Address = BYTE *;

        struct Jump {
            Jump(Address from, Address to)
                : from(from)
                , to(to)
            {
            }
            Address from;
            Address to;
        };

        struct Call : public Jump {
            Call(Address from, Address to, Address ret)
                : Jump(from, to)
                , ret(ret)
            {
            }
            Address ret;
        };

        class Function {
        public:
            Function();
            Function(ZydisDecoder const &decoder, Address address);

            Address const address;

            inline const std::vector<ZydisDecodedInstruction>
            get_instructions() const
            {
                return instructions_;
            }

            inline const std::map<Address, Jump> get_jumps_inside() const { return jumps_inside_; }
            inline const std::map<Address, Jump> get_jumps_outside() const { return jumps_outside_; }
            inline const std::map<Address, Call> get_calls() const { return calls_; }

        private:
            std::vector<ZydisDecodedInstruction> instructions_;
            std::map<Address, Jump> jumps_inside_;
            std::map<Address, Jump> jumps_outside_;
            std::map<Address, Call> calls_;
        };

        Restruc(std::filesystem::path const &pe_path);

        void analyze();

    private:
        void add_function(ZydisDecoder const &decoder, Address address);

        PE pe_;

        std::map<Address, Function> functions_;
        std::unordered_set<Address> unvisited_functions_;
    };

}
