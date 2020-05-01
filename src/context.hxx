#pragma once

#include "core.hxx"
#include "virtual_memory.hxx"

#include <Zydis/Zydis.h>

#include <optional>
#include <unordered_map>
#include <vector>

namespace rstc {

    class Context;
    using ContextPtr = std::unique_ptr<Context>;
    using ContextPtrs = std::vector<ContextPtr>;

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

        Context(Address source);
        Context(Context const *parent, bool flatten = false);

        bool registers_equal(Context const &other) const;

        ValueSource get(ZydisRegister reg) const;
        VirtualMemory::Sources get(uintptr_t address, size_t size) const;

        void set(ZydisRegister reg, Address source, Value value = std::nullopt);
        void set(ZydisRegister reg, ValueSource valsrc);
        void set(uintptr_t address, size_t size, Address source);

        void flattenize();

        ContextPtr make_child() const;
        ContextPtr make_flatten_child() const;

        inline std::unordered_map<ZydisRegister, ValueSource> const &
        get_changed_registers()
        {
            return registers_;
        }

    private:
        void set_all_registers_zero(Address source);

        Context const *parent_;
        bool flatten_;
        std::unordered_map<ZydisRegister, ValueSource> registers_;
        VirtualMemory memory_;
    };

}