#pragma once

#include "core.hxx"

#include "contexts.hxx"
#include "pe.hxx"

#include <Zydis/Zydis.h>

#include <functional>
#include <map>
#include <memory>
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
        enum AnalysisStatus : bool {
            Stop = false,
            Next = true,
            Complete = Stop,
            AlreadyAnalyzed = Stop,
            UnknownJump = Stop,
            OuterJump = Stop,
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

        struct ContextPropagationResult {
            Contexts new_contexts;
            ZydisDecodedInstruction const *instruction = nullptr;
        };

        Flo(PE const &pe,
            Address entry_point = nullptr,
            std::optional<Address> end = std::nullopt);

        AnalysisResult analyze(Address address, Instruction instr);
        Address get_unanalized_inner_jump_dst() const;

        void
        promote_unknown_jumps(Jump::Type type,
                              std::function<bool(Address)> predicate = nullptr);

        void filter_contexts(Address address, Contexts &contexts);
        ContextPropagationResult propagate_contexts(Address address,
                                                    Contexts contexts);

        ZydisDecodedInstruction const *get_instruction(Address address) const;

        bool is_inside(Address address) const;

        static Address
        get_jump_destination(Address address,
                             ZydisDecodedInstruction const &instruction);
        static std::unordered_set<Address>
        get_jump_destinations(PE const &pe,
                              Address address,
                              ZydisDecodedInstruction const &instruction,
                              Contexts const &context);
        static Address
        get_call_destination(Address address,
                             ZydisDecodedInstruction const &instruction);
        static std::optional<uintptr_t>
        get_memory_address(ZydisDecodedOperand const &op,
                           Context const &context);

        static bool is_conditional_jump(ZydisMnemonic mnemonic);

        std::vector<Context const *> get_contexts(Address address) const;
        inline std::multimap<Address, Context> const &get_contexts() const
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
        std::optional<Address> const end;

    private:
        struct Operand {
            virt::Value value = virt::Value();
            std::optional<uintptr_t> address = std::nullopt;
            ZydisRegister reg = ZYDIS_REGISTER_NONE;
        };

        using EmulationCallback = std::function<virt::Value(
            virt::Value const &dst,
            virt::Value const &src)>;
        using EmulationCallbackAction =
            std::function<uintptr_t(uintptr_t, uintptr_t)>;

        Jump::Type get_jump_type(Address dst,
                                 Address src,
                                 Address next,
                                 bool unconditional) const;

        SPManipulationType analyze_stack_pointer_manipulation(
            ZydisDecodedInstruction const &instruction);
        void visit(Address address);
        bool promote_unknown_jumps(Address dst, Jump::Type new_type);

        Context const &emplace_context(Address address, Context &&context);
        void emulate(Address address,
                     ZydisDecodedInstruction const &instruction,
                     Context &context);
        void emulate_instruction(ZydisDecodedInstruction const &instruction,
                                 Context &context,
                                 Address address,
                                 EmulationCallback const &callback);
        void
        emulate_instruction_lea(ZydisDecodedInstruction const &instruction,
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

        bool stack_depth_is_ambiguous() const;

        void add_jump(Jump::Type type, Address dst, Address src);
        void add_call(Address dst, Address src, Address ret);

        PE const &pe_;
        Disassembly disassembly_;
        std::multimap<Address, Context> contexts_;
        Jumps inner_jumps_;
        Jumps outer_jumps_;
        Jumps unknown_jumps_;
        Calls calls_;
        int stack_depth_ = 0;
        bool stack_depth_was_modified_ = false;

        static std::unordered_map<ZydisMnemonic, EmulationCallbackAction>
            emulation_callback_actions_;
    };

}
