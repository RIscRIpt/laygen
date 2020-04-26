#pragma once

#include "core.hxx"
#include "virtual_memory.hxx"

#include <Zydis/Zydis.h>

#include <immintrin.h>

#include <list>
#include <unordered_map>
#include <unordered_set>
#include <variant>

namespace rstc {

    class Context;
    using ContextPtr = std::unique_ptr<Context>;
    using Contexts = std::list<ContextPtr>;

    class Context {
    public:
        using RegisterValue = std::variant<uintptr_t, __m64, __m512>;

        struct RegisterValueSource {
            RegisterValue value;
            Address source;
        };

        Context(Context const *parent);

        Context const *const parent;

        std::pair<RegisterValueSource, Context const *> get(ZydisRegister reg) const;
        VirtualMemory::MemoryWithSources get(uintptr_t address,
                                             size_t size) const;

        void set(ZydisRegister reg, RegisterValue value, Address source);
        void set(ZydisRegister reg, RegisterValueSource regval);
        void set(uintptr_t address, std::vector<Byte> memory, Address source);

        void set_all_registers_zero(Address source);

        ContextPtr get_flatten() const;
        ContextPtr make_child() const;

        inline std::unordered_map<ZydisRegister, RegisterValueSource> const &
        get_changed_registers()
        {
            return changed_registers_;
        }

    private:
        std::unordered_map<ZydisRegister, RegisterValueSource> changed_registers_;
        VirtualMemory changed_memory_;
    };

}