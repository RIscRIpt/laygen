#include "contexts.hxx"

#include <algorithm>
#include <atomic>
#include <functional>
#include <stdexcept>
#include <unordered_set>

using namespace rstc;

static std::atomic<size_t> GLOBAL_ID = 0;

template<class T>
static inline void hash_combine(std::size_t &seed, const T &v)
{
    std::hash<T> hasher;
    seed ^= hasher(v) * 0x5851F42D4C957F2D + 0x14057B7EF767814F;
}

Context::Context(Address source)
    : hash_(0)
    , id_(++GLOBAL_ID)
    , caller_id_(0)
    , registers_()
    , memory_(source)
{
    set_all_registers_zero(source);
}

Context::Context(Context const *parent, ParentRole parent_role)
    : hash_(parent->hash_)
    , id_(++GLOBAL_ID)
    , caller_id_(parent_role == ParentRole::Caller ? parent->id_ :
                                                     parent->caller_id_)
    , registers_(&parent->registers_)
    , memory_(&parent->memory_)
{
}

Context::RegisterValueSource Context::get_register(ZydisRegister reg) const
{
    return registers_.get(reg);
}

Context::MemoryValues Context::get_memory(uintptr_t address, size_t size) const
{
    return memory_.get(address, size);
}

void Context::set_register(ZydisRegister reg,
                           Address source,
                           Context::RegisterValue value)
{
    set_register(reg, virt::Registers::ValueSource{ value, source });
}

void Context::set_register(ZydisRegister reg,
                           virt::Registers::ValueSource valsrc)
{
    if (!registers_.is_tracked(reg)) {
        return;
    }
    if (auto old = get_register(reg); old) {
        hash_combine(hash_, old->source);
        if (old->value) {
            hash_combine(hash_, *old->value);
        }
        // Don't "un"-hash `reg`,
        // as we will hash it only if old value didn't exist
    }
    else {
        hash_combine(hash_, reg);
    }
    if (valsrc.value) {
        hash_combine(hash_, *valsrc.value);
    }
    hash_combine(hash_, valsrc.source);
    registers_.set(reg, valsrc);
}

void Context::set_all_registers_zero(Address source)
{
    for (auto const &[zydis_reg, reg] : virt::Registers::register_map) {
        set_register(zydis_reg, source, 0);
    }
}

void Context::set_memory(uintptr_t address,
                         Address source,
                         RegisterValue value,
                         size_t size)
{
    memory_.set(address, source, value, size);
}

Context Context::make_child(ParentRole parent_role) const
{
    return Context(this, parent_role);
}
