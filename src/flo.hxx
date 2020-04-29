#pragma once

#include "core.hxx"

#include "context.hxx"
#include "pe.hxx"

#include <Zydis/Zydis.h>

#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>

namespace rstc {

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
        Call(Address dst, Address src, Address ret, int args = -1)
            : Jump(Jump::Outer, dst, src)
            , ret(ret)
            , args(args == -1 ? std::optional<int>(std::nullopt) : args)
        {
        }
        Address const ret;
        std::optional<int> args;
    };

    // Destination -> Call
    using Calls = std::multimap<Address, Call>;

    using Disassembly = std::map<Address, Instruction>;

    class Flo {
    public:
        enum AnalysisStatus {
            Stop,
            Complete,
            UnknownJump,
            Next = 0x8000000,
            InnerJump,
            OuterJump,
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

        Flo(Address entry_point = nullptr);

        AnalysisResult analyze(Address address,
                               Instruction instr,
                               std::optional<Address> flo_end = std::nullopt);
        Address get_unanalized_inner_jump_dst() const;

        void
        promote_unknown_jumps(Jump::Type type,
                              std::function<bool(Address)> predicate = nullptr);

        std::pair<ContextPtr, ZydisDecodedInstruction const *>
        propagate_contexts(Address address, ContextPtr context);

        ZydisDecodedInstruction const *get_instruction(Address address) const;

        static Address
        get_jump_destination(Address address,
                             ZydisDecodedInstruction const &instruction);
        static Address
        get_jump_destination(PE const &pe,
                             Address address,
                             ZydisDecodedInstruction const &instruction,
                             Context const &context);
        static Address
        get_call_destination(Address address,
                             ZydisDecodedInstruction const &instruction);
        static std::pair<Context::Value, size_t>
        get_memory_address(ZydisDecodedOperand const &op,
                           Context const &context);

        static bool is_conditional_jump(ZydisMnemonic mnemonic);

        std::vector<Context const *> get_contexts(Address address) const;
        inline std::multimap<Address, ContextPtr> const &get_contexts() const
        {
            return contexts_;
        }

        inline Disassembly const &get_disassembly() const
        {
            return disassembly_;
        }
        inline Jumps const &get_inner_jumps() const { return inner_jumps_; }
        inline Jumps const &get_outer_jumps() const { return outer_jumps_; }
        inline Jumps const &get_unknown_jumps() const { return unknown_jumps_; }
        inline Calls const &get_calls() const { return calls_; }

        Address const entry_point;

    private:
        bool is_inside(Address address,
                       std::optional<Address> flo_end = std::nullopt) const;
        Jump::Type
        get_jump_type(Address dst,
                      Address src,
                      Address next,
                      bool unconditional,
                      std::optional<Address> flo_end = std::nullopt) const;

        SPManipulationType analyze_stack_pointer_manipulation(
            ZydisDecodedInstruction const &instruction);
        void visit(Address address);
        bool promote_unknown_jumps(Address dst, Jump::Type new_type);

        static void emulate(Address address,
                            ZydisDecodedInstruction const &instruction,
                            Context &context);

        bool stack_depth_is_ambiguous() const;

        void add_jump(Jump::Type type, Address dst, Address src);
        void add_call(Address dst, Address src, Address ret);

        Disassembly disassembly_;
        std::multimap<Address, ContextPtr> contexts_;
        Jumps inner_jumps_;
        Jumps outer_jumps_;
        Jumps unknown_jumps_;
        Calls calls_;
        int stack_depth_ = 0;
        bool stack_depth_was_modified_ = false;
    };

}
