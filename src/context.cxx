#include "contexts.hxx"

#include "utils/hash.hxx"

#include <algorithm>
#include <atomic>
#include <functional>
#include <stdexcept>
#include <unordered_set>

using namespace rstc;

Context::Context(std::nullptr_t)
    : hash_(0)
    , registers_()
    , memory_(nullptr)
{
    for (auto const &[zydis_reg, reg] : virt::Registers::register_map) {
        set_register(zydis_reg, virt::make_symbolic_value(nullptr));
    }
}

Context::Context(Context const *parent)
    : hash_(parent->hash_)
    , registers_(&parent->registers_)
    , memory_(&parent->memory_)
{
}

std::optional<virt::Value> Context::get_register(ZydisRegister reg) const
{
    return registers_.get(reg);
}

Context::MemoryValues Context::get_memory(uintptr_t address, size_t size) const
{
    return memory_.get(address, size);
}

void Context::set_register(ZydisRegister reg, virt::Value value)
{
    if (!registers_.is_tracked(reg)) {
        return;
    }
    if (auto old = get_register(reg); old) {
        utils::hash::reverse(hash_, old->source());
        if (old->is_symbolic()) {
            utils::hash::reverse(hash_, old->symbol().offset());
            utils::hash::reverse(hash_, old->symbol().id());
        }
        else {
            utils::hash::reverse(hash_, old->value());
        }
        // Don't "un"-hash `reg`,
        // as we will hash it only if old value didn't exist
    }
    else {
        utils::hash::combine(hash_, reg);
    }
    if (value.is_symbolic()) {
        utils::hash::combine(hash_, value.symbol().id());
        utils::hash::combine(hash_, value.symbol().offset());
    }
    else {
        utils::hash::combine(hash_, value.value());
    }
    utils::hash::combine(hash_, value.source());
    registers_.set(reg, value);
}

void Context::set_memory(uintptr_t address, virt::Value value)
{
    memory_.set(address, value);
}

Context Context::make_child() const
{
    return Context(this);
}
