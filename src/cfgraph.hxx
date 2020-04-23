#pragma once

#include "pe.hxx"

#include <Zydis/Zydis.h>

#include <functional>
#include <map>
#include <memory>

namespace rstc {

    using Address = BYTE *;
    using Instruction = std::unique_ptr<ZydisDecodedInstruction>;

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

    using Disassembly = std::map<Address, Instruction>;

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

        CFGraph(Address entry_point = nullptr);

        AnalysisResult analyze(PE &pe, Address address, Instruction instr);
        Address get_unanalized_inner_jump_dst() const;

        void
        promote_unknown_jumps(Jump::Type type,
                              std::function<bool(Address)> predicate = nullptr);

        inline Disassembly const &get_disassembly() const
        {
            return disassembly;
        }
        inline Jumps const &get_inner_jumps() const { return inner_jumps; }
        inline Jumps const &get_outer_jumps() const { return outer_jumps; }
        inline Jumps const &get_unknown_jumps() const { return unknown_jumps; }
        inline Calls const &get_calls() const { return calls; }

        Address const entry_point;

    private:
        bool is_inside(Address address) const;
        Jump::Type get_jump_type(Address dst, Address src, Address next, bool unconditional) const;

        SPManipulationType analyze_stack_pointer_manipulation(
            ZydisDecodedInstruction const &instruction);
        void visit(Address address);
        bool promote_unknown_jumps(Address dst, Jump::Type new_type);

        bool stack_depth_is_ambiguous() const;

        void add_jump(Jump::Type type, Address dst, Address src);
        void add_call(Address dst, Address src, Address ret);

        static bool is_conditional_jump(ZydisMnemonic mnemonic);

        Disassembly disassembly;
        Jumps inner_jumps;
        Jumps outer_jumps;
        Jumps unknown_jumps;
        Calls calls;
        int stack_depth = 0;
        bool stack_was_modified = false;
    };

}