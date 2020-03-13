#pragma once

#include "pe.hxx"

#include <Zydis/Zydis.h>

#include <vector>
#include <map>
#include <unordered_set>

namespace rstc {

    class Restruc {
    public:
        struct Jump {
            Jump(BYTE *from, BYTE *to)
                : from(from)
                , to(to)
            {
            }

            BYTE *from;
            BYTE *to;
        };

        class Function {
        public:
            Function();
            Function(ZydisDecoder const &decoder, BYTE *address);

            BYTE *const address;

            inline const std::vector<ZydisDecodedInstruction>
            get_instructions() const
            {
                return instructions_;
            }

            inline const std::vector<Jump> get_calls() const { return calls_; }
            inline const std::vector<Jump> get_jumps() const { return jumps_; }

        private:
            std::vector<ZydisDecodedInstruction> instructions_;
            std::vector<Jump> calls_;
            std::vector<Jump> jumps_;
        };

        Restruc(std::filesystem::path const &pe_path);

        void analyze();

    private:
        PE pe_;

        std::map<BYTE*, Function> functions_;
        std::unordered_set<BYTE *> unvisited_functions_;
    };

}
