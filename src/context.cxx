#include "context.hxx"

#include <stdexcept>

using namespace rstc;

static const Register REGISTERS[] = {
    Register::RAX, Register::RBX, Register::RCX, Register::RDX,
    Register::RBP, Register::RSP, Register::RDI, Register::RSI,
    Register::R8,  Register::R9,  Register::R10, Register::R11,
    Register::R12, Register::R13, Register::R14, Register::R15,
};

Context::Context(Context const *parent)
    : parent(parent)
{
}

std::pair<Context::RegisterValue, Context const *>
Context::get(Register reg) const
{
    Context const *c = this;
    do {
        if (auto it = c->changed_registers_.find(reg);
            it != c->changed_registers_.end()) {
            return { it->second, c };
        }
        c = c->parent;
    } while (c);
    assert(false && "root Context doesn't have values of all registers");
    return {};
}

VirtualMemory::MemoryWithSources Context::get(uintptr_t address,
                                              size_t size) const
{
    if (parent != nullptr) {
        throw std::runtime_error(
            "Context::get for memory works only with flattened Context");
    }
    return changed_memory_.get(address, size);
}

void Context::set(Register reg, RegisterValue regval)
{
    changed_registers_.insert_or_assign(reg, regval);
}

void Context::set(Register reg, uintptr_t value, Address source)
{
    changed_registers_.insert_or_assign(reg, RegisterValue{ value, source });
}

void Context::set(uintptr_t address, std::vector<Byte> memory, Address source)
{
    changed_memory_.assign(address, std::move(memory), source);
}

std::unique_ptr<Context> Context::get_flatten() const
{
    auto flatten = std::make_unique<Context>(nullptr);
    for (auto reg : REGISTERS) {
        flatten->set(reg, get(reg).first);
    }
    // TODO: flatten changed_memory_
    return nullptr;
}
