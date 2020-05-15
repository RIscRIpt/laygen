#pragma once

#include "core.hxx"

#include "virtual/memory.hxx"
#include "virtual/registers.hxx"

#include <Zydis/Zydis.h>

#include <memory>
#include <optional>
#include <unordered_map>

namespace rstc {

    class Context {
    public:
        enum class ParentRole {
            // Current Context has parent_caller_id_
            // equal to parent's caller_id_.
            Default,

            // Current Context has parent_caller_id_
            // equal to parent's id_.
            Caller,
        };

        using RegisterValue = virt::Registers::Value;
        using RegisterValueSource = std::optional<virt::Registers::ValueSource>;
        using MemoryValues = virt::Memory::Values;

        Context() = delete;
        Context(Address source);
        Context(Context const *parent,
                ParentRole parent_role = ParentRole::Default);

        Context(Context const &) = delete;
        Context(Context &&other) = default;

        Context &operator=(Context const &) = delete;
        Context &operator=(Context &&rhs) = default;

        RegisterValueSource get_register(ZydisRegister reg) const;
        MemoryValues get_memory(uintptr_t address, size_t size) const;

        void set_register(ZydisRegister reg,
                          Address source,
                          RegisterValue value = std::nullopt);
        void set_register(ZydisRegister reg,
                          virt::Registers::ValueSource valsrc);
        void
        set_memory(uintptr_t address,
                   Address source,
                   RegisterValue value = std::nullopt,
                   size_t size = sizeof(virt::Registers::Value::value_type));

        Context make_child(ParentRole parent_role) const;

        inline bool operator<(Context const &rhs) const
        {
            return hash_ < rhs.hash_;
        }
        inline bool operator==(Context const &rhs) const
        {
            return hash_ == rhs.hash_;
        }
        inline bool operator!=(Context const &rhs) const
        {
            return hash_ != rhs.hash_;
        }

        inline size_t get_hash() const { return hash_; }
        inline size_t get_id() const { return id_; }
        inline size_t get_caller_id() const { return caller_id_; }

    private:
        void set_all_registers_zero(Address source);

        size_t hash_;
        size_t id_;
        size_t caller_id_;
        virt::Registers registers_;
        virt::Memory memory_;
    };

}
