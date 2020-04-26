#pragma once

#include "core.hxx"
#include "virtual_memory.hxx"

#include <unordered_map>

namespace rstc {

    enum class Register : char {
        RAX,
        RBX,
        RCX,
        RDX,
        RBP,
        RSP,
        RDI,
        RSI,
        R8,
        R9,
        R10,
        R11,
        R12,
        R13,
        R14,
        R15,
    };

    class Context {
    public:
        struct RegisterValue {
            uintptr_t value;
            Address source;
        };

        Context(Context const *parent);

        Context const *const parent;

        std::pair<RegisterValue, Context const *> get(Register reg) const;
        VirtualMemory::MemoryWithSources get(uintptr_t address,
                                             size_t size) const;

        void set(Register reg, RegisterValue regval);
        void set(Register reg, uintptr_t value, Address source);
        void set(uintptr_t address, std::vector<Byte> memory, Address source);

        std::unique_ptr<Context> get_flatten() const;

    private:
        std::unordered_map<Register, RegisterValue> changed_registers_;
        VirtualMemory changed_memory_;
    };

}