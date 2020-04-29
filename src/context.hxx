#pragma once

#include "core.hxx"
#include "virtual_memory.hxx"

#include <Zydis/Zydis.h>

#include <optional>
#include <unordered_map>
#include <unordered_set>

namespace rstc {

    class Context;
    using ContextPtr = std::unique_ptr<Context>;

    class Context {
    public:
        using Value = std::optional<uintptr_t>;
        struct ValueSource {
            Value value;
            Address source;
            inline bool operator==(ValueSource const& other) const
            {
                return value == other.value && source == other.source;
            }
            inline bool operator!=(ValueSource const& other) const
            {
                return !(*this == other);
            }
        };

        Context(Address source);
        Context(Context const *parent);

        Context const *const parent = nullptr;

        bool registers_equal(Context const &other) const;

        ValueSource get(ZydisRegister reg) const;
        VirtualMemory::Sources get(uintptr_t address, size_t size) const;

        void set(ZydisRegister reg, Address source, Value value = std::nullopt);
        void set(ZydisRegister reg, ValueSource valsrc);
        void set(uintptr_t address, size_t size, Address source);

        ContextPtr make_flatten() const;
        ContextPtr make_child() const;

        inline std::unordered_map<ZydisRegister, ValueSource> const &
        get_changed_registers()
        {
            return registers_;
        }
        
    private:
        void set_all_registers_zero(Address source);

        bool flatten;
        std::unordered_map<ZydisRegister, ValueSource> registers_;
        VirtualMemory memory_;
    };

}