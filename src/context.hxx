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
        using MemoryValues = virt::Memory::Values;

        Context() = delete;
        Context(std::nullptr_t);
        Context(Context const *parent);

        Context(Context const &) = delete;
        Context(Context &&other) = default;

        Context &operator=(Context const &) = delete;
        Context &operator=(Context &&rhs) = default;

        std::optional<virt::Value> get_register(ZydisRegister reg) const;
        MemoryValues get_memory(uintptr_t address, size_t size) const;

        void set_register(ZydisRegister reg, virt::Value value);
        void set_memory(uintptr_t address, virt::Value value);

        Context make_child() const;

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

    private:
        size_t hash_;
        virt::Registers registers_;
        virt::Memory memory_;
    };

}
