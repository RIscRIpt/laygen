#pragma once

#include "core.hxx"
#include "virtual_memory.hxx"

#include <Zydis/Zydis.h>

#include <optional>
#include <unordered_map>

namespace rstc {

    class Context {
    public:
        enum class ParentRole
        {
            // Current Context is flatten, and has no parent
            None,

            // Current Context is flatten, has no parent,
            // and has parent_caller_id_ equal to parent's id_.
            Caller,

            // Current Context is not flatten, and has parent
            Default,
        };

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
        Context(Context const *parent,
                ParentRole parent_role = ParentRole::Default);

        Context(Context const &) = delete;
        Context(Context &&other) = default;

        Context &operator=(Context const &) = delete;
        Context &operator=(Context &&rhs) = default;

        std::optional<ValueSource> get(ZydisRegister reg) const;
        VirtualMemory::Sources get(uintptr_t address, size_t size) const;

        void set(ZydisRegister reg, Address source, Value value = std::nullopt);
        void set(ZydisRegister reg, ValueSource valsrc);
        void set(uintptr_t address, size_t size, Address source);

        void flatten();

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
        inline std::unordered_map<ZydisRegister, ValueSource> const &
        get_changed_registers()
        {
            return registers_;
        }

    private:
        void set_all_registers_zero(Address source);

        Context const *parent_;
        size_t hash_;
        size_t id_;
        size_t caller_id_;
        std::unordered_map<ZydisRegister, ValueSource> registers_;
        VirtualMemory memory_;
        bool flatten_;
    };

}
