#pragma once

#include "core.hxx"

#include "value.hxx"

#include <Zydis/Zydis.h>

#include <memory>
#include <optional>
#include <unordered_map>
#include <unordered_set>

namespace rstc::virt {

    class Registers {
    public:
        enum Reg {
            RAX,
            RCX,
            RDX,
            RBX,
            RSP,
            RBP,
            RSI,
            RDI,
            R8,
            R9,
            R10,
            R11,
            R12,
            R13,
            R14,
            R15,
            X87CONTROL,
            X87STATUS,
            X87TAG,
            MM0,
            MM1,
            MM2,
            MM3,
            MM4,
            MM5,
            MM6,
            MM7,
            ZMM0,
            ZMM1,
            ZMM2,
            ZMM3,
            ZMM4,
            ZMM5,
            ZMM6,
            ZMM7,
            ZMM8,
            ZMM9,
            ZMM10,
            ZMM11,
            ZMM12,
            ZMM13,
            ZMM14,
            ZMM15,
            ZMM16,
            ZMM17,
            ZMM18,
            ZMM19,
            ZMM20,
            ZMM21,
            ZMM22,
            ZMM23,
            ZMM24,
            ZMM25,
            ZMM26,
            ZMM27,
            ZMM28,
            ZMM29,
            ZMM30,
            ZMM31,
            RFLAGS,

            REGISTERS_COUNT,
        };

        Registers(Registers const *parent = nullptr);

        Registers(Registers const &) = delete;
        Registers(Registers &&other) = default;

        Registers &operator=(Registers const &) = delete;
        Registers &operator=(Registers &&rhs) = default;

        std::optional<Value> get(ZydisRegister zydis_reg) const;
        void set(ZydisRegister zydis_reg, Value value);

        bool is_tracked(ZydisRegister zydis_reg) const;

        static std::optional<Reg> from_zydis(ZydisRegister zydis_reg);
        static ZydisRegister promote(ZydisRegister zydis_reg);

        static const std::unordered_map<ZydisRegister, Registers::Reg>
            register_map;

    private:
        struct Holder {
            std::shared_ptr<void> l = nullptr;
            std::shared_ptr<void> r = nullptr;
        };

        void initialize_holder(Holder &holder, size_t begin, size_t end);

        std::shared_ptr<void> holder_;

        static const std::unordered_map<ZydisRegister, ZydisRegister>
            reg_promotion_map_;
        static const std::unordered_set<ZydisRegister> legacy_ho_part_;
    };

}
