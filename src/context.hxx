#pragma once

#include "core.hxx"
#include "virtual_memory.hxx"

#include <Zydis/Zydis.h>

#include <optional>
#include <set>
#include <unordered_map>

namespace rstc {

    class Context {
    public:
        using Value = std::optional<uintptr_t>;
        struct ValueSource {
            Value value;
            Address source;
            inline bool operator==(ValueSource const &other) const
            {
                return value == other.value && source == other.source;
            }
            inline bool operator!=(ValueSource const &other) const
            {
                return !(*this == other);
            }
        };

        Context() = delete;
        Context(Address source);
        Context(Context const *parent, bool flatten = false);

        Context(Context const &) = delete;
        Context(Context &&other) = default;

        Context &operator=(Context const &) = delete;
        Context &operator=(Context &&rhs) = default;

        ValueSource get(ZydisRegister reg) const;
        VirtualMemory::Sources get(uintptr_t address, size_t size) const;

        void set(ZydisRegister reg, Address source, Value value = std::nullopt);
        void set(ZydisRegister reg, ValueSource valsrc);
        void set(uintptr_t address, size_t size, Address source);

        void flattenize();

        Context make_child() const;
        Context make_flatten_child() const;

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
        inline std::unordered_map<ZydisRegister, ValueSource> const &
        get_changed_registers()
        {
            return registers_;
        }

    private:
        void set_all_registers_zero(Address source);

        Context const *parent_;
        bool flatten_;
        size_t hash_;
        std::unordered_map<ZydisRegister, ValueSource> registers_;
        VirtualMemory memory_;
    };

    using Contexts = std::set<Context>;
}