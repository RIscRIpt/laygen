#pragma once

#include "core.hxx"

#include "contexts.hxx"
#include "pe.hxx"

#include <Zydis/Zydis.h>

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <variant>

namespace rstc {

    struct Jump {
        enum Type {
            Unknown,
            Inner,
            Outer,
        };
        Jump(Type type,
             ZydisDecodedInstruction const &ins,
             Address dst,
             Address src)
            : ins(ins)
            , type(type)
            , dst(dst)
            , src(src)
        {
        }
        ZydisDecodedInstruction const &ins;
        Type const type;
        Address const dst;
        Address const src;
    };

    // Destination -> Jump
    using Jumps = std::multimap<Address, Jump>;

    struct Call : public Jump {
        Call(ZydisDecodedInstruction const &ins,
             Address dst,
             Address src,
             Address ret)
            : Jump(Jump::Outer, ins, dst, src)
            , ret(ret)
        {
        }
        Address const ret;
    };

    // Destination -> Call
    using Calls = std::multimap<Address, Call>;

    struct Cycle {
        struct ExitCondition {
            ExitCondition(ZydisDecodedInstruction const *instruction,
                          ZydisMnemonic const jump)
                : instruction(instruction)
                , jump(jump)
            {
            }
            ZydisDecodedInstruction const *const instruction;
            ZydisMnemonic const jump;
        };
        using ExitConditions = std::multimap<ZydisRegister, ExitCondition>;
        // First and last instructions. Last instruction is either JMP or Jcc.
        Cycle(Address first, Address last, ExitConditions &&exit_conditions)
            : first(first)
            , last(last)
            , exit_conditions(std::move(exit_conditions))
        {
        }
        Address const first;
        Address const last;
        ExitConditions const exit_conditions;
    };

    // Address of last instruction -> Cycle
    using Cycles = std::map<Address, Cycle>;

    using Disassembly = std::map<Address, Instruction>;

    class Flo {
    public:
        enum AnalysisStatus : bool {
            Stop = false,
            Next = true,
            Complete = Stop,
            Unreachable = Stop,
            AlreadyAnalyzed = Stop,
            UnknownJump = Stop,
            OuterJump = Stop,
            CycleJump = Stop,
            InnerJump = Next,
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

        Flo(PE const &pe,
            Address entry_point = nullptr,
            Address reference = nullptr,
            std::optional<Address> end = std::nullopt);

        AnalysisResult analyze(Address address, Instruction instr);
        Address get_unanalized_inner_jump_dst() const;

        void
        promote_unknown_jumps(Jump::Type type,
                              std::function<bool(Address)> predicate = nullptr);

        void set_end(Address end);

        void add_cycle(Contexts const &contexts, Address first, Address last);
        void add_reference(Address reference);

        bool is_inside(Address address) const;

        static Address
        get_jump_destination(Address address,
                             ZydisDecodedInstruction const &instruction);
        std::unordered_set<Address>
        get_jump_destinations(Address address,
                              ZydisDecodedInstruction const &instruction,
                              Contexts const &contexts);
        static Address
        get_call_destination(Address address,
                             ZydisDecodedInstruction const &instruction);

        static bool is_any_jump(ZydisMnemonic mnemonic);
        static bool is_conditional_jump(ZydisMnemonic mnemonic);

        ZydisDecodedInstruction const *get_instruction(Address address) const;

        inline std::set<Address> const &get_references() const
        {
            return references_;
        }

        inline Disassembly const &get_disassembly() const
        {
            return disassembly_;
        }
        inline Jumps const &get_inner_jumps() const { return inner_jumps_; }
        inline Jumps const &get_outer_jumps() const { return outer_jumps_; }
        inline Jumps const &get_unknown_jumps() const { return unknown_jumps_; }
        inline Calls const &get_calls() const { return calls_; }

        std::vector<Cycle const *> get_cycles(Address address) const;
        inline Cycles const &get_cycles() const { return cycles_; }

        inline std::optional<Address> const &end() const { return end_; }
        inline std::mutex &mutex() { return modify_access_mutex_; }

        Address const entry_point;

    private:
        bool should_be_unreachable(ZydisDecodedInstruction const &instruction);
        Jump::Type get_jump_type(Address dst,
                                 Address src,
                                 Address next,
                                 bool unconditional) const;

        SPManipulationType analyze_stack_pointer_manipulation(
            ZydisDecodedInstruction const &instruction);
        void visit(Address address);
        bool promote_unknown_jumps(Address dst, Jump::Type new_type);

        static bool
        modifies_flags_register(ZydisDecodedInstruction const &instruction);

        bool stack_depth_is_ambiguous() const;

        void add_jump(Jump::Type type,
                      ZydisDecodedInstruction const &ins,
                      Address dst,
                      Address src);
        void add_call(ZydisDecodedInstruction const &ins,
                      Address dst,
                      Address src,
                      Address ret);

        std::optional<Address> end_;
        std::mutex modify_access_mutex_;
        PE const &pe_;
        Disassembly disassembly_;
        std::set<Address> references_;
        Jumps inner_jumps_;
        Jumps outer_jumps_;
        Jumps unknown_jumps_;
        Calls calls_;
        Cycles cycles_;
        int stack_depth_ = 0;
        bool stack_depth_was_modified_ = false;
    };

}
