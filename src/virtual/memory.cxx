#include "memory.hxx"

#include <algorithm>

using namespace rstc;
using namespace rstc::virt;

Memory::Value::Value(Address source, Byte byte)
    : byte(byte)
    , source(source)
{
}

Memory::Values::Values(size_t size, Address default_source)
    : bytes(size)
    , sources(size, default_source)
{
}

Memory::Values::operator Registers::Value() const
{
    if (bytes.size() < sizeof(Registers::Value::value_type)) {
        // TODO: use sources
        return {};
    }
    // MSVC (un)defined behaviour
    return *reinterpret_cast<Registers::Value::value_type const*>(bytes.data());
}

Memory::Memory(Address source)
    : default_source_(source)
    , holder_(std::make_shared<Holder>())
{
}

Memory::Memory(Memory const *parent)
    : default_source_(parent->default_source_)
    , holder_(parent->holder_)
{
}

void Memory::set(uintptr_t address, Address source, Registers::Value value)
{
    std::vector<Byte> bytes;
    if (value) {
        bytes.resize(sizeof(*value));
        std::copy(reinterpret_cast<Byte *>(&*value),
                  reinterpret_cast<Byte *>(&*value) + sizeof(*value),
                  bytes.begin());
    }
    set(address, source, bytes);
}

void Memory::set(uintptr_t address,
                 Address source,
                 std::vector<Byte> const &bytes)
{
    if (bytes.size() <= 0) {
        return;
    }
    auto tree = std::static_pointer_cast<Holder>(holder_);
    auto new_tree = std::make_shared<Holder>();
    holder_ = new_tree;
    uintptr_t begin = 0;
    uintptr_t end = ~0;
    uintptr_t address_end = address + bytes.size();
    while (begin < end - 3) {
        uintptr_t middle = begin + (end - begin) / 2;
        if (address < middle && address_end < middle) {
            end = middle;
            new_tree->l = std::make_shared<Holder>();
            if (tree) {
                new_tree->r = tree->r;
                tree = std::static_pointer_cast<Holder>(tree->l);
            }
            new_tree = std::static_pointer_cast<Holder>(new_tree->l);
        }
        else if (address >= middle && address_end >= middle) {
            begin = middle;
            new_tree->r = std::make_shared<Holder>();
            if (tree) {
                new_tree->l = tree->l;
                tree = std::static_pointer_cast<Holder>(tree->r);
            }
            new_tree = std::static_pointer_cast<Holder>(new_tree->r);
        }
        else {
            break;
        }
    }
    for (uintptr_t i = address; i != address_end; i++) {
        uintptr_t index = i - address;
        set_value(tree, new_tree, begin, end, i, source, bytes[index]);
        tree = new_tree;
    }
}

void Memory::set_value(std::shared_ptr<Holder> tree,
                       std::shared_ptr<Holder> new_tree,
                       uintptr_t begin,
                       uintptr_t end,
                       uintptr_t address,
                       Address source,
                       Byte byte)
{
    while (true) {
        uintptr_t middle = begin + (end - begin) / 2;
        if (address < middle) {
            end = middle;
            if (tree) {
                new_tree->r = tree->r;
            }
            if (begin < end - 1) {
                if (tree) {
                    tree = std::static_pointer_cast<Holder>(tree->l);
                }
                new_tree->l = std::make_shared<Holder>();
                new_tree = std::static_pointer_cast<Holder>(new_tree->l);
            }
            else {
                new_tree->l = std::make_shared<Value>(source, byte);
                break;
            }
        }
        else {
            begin = middle;
            if (tree) {
                new_tree->l = tree->l;
            }
            if (begin < end - 1) {
                if (tree) {
                    tree = std::static_pointer_cast<Holder>(tree->r);
                }
                new_tree->r = std::make_shared<Holder>();
                new_tree = std::static_pointer_cast<Holder>(new_tree->r);
            }
            else {
                new_tree->r = std::make_shared<Value>(source, byte);
                break;
            }
        }
    }
}

Memory::Values Memory::get(uintptr_t address, size_t size) const
{
    Values values(size, default_source_);
    auto tree = std::static_pointer_cast<Holder>(holder_);
    uintptr_t begin = 0;
    uintptr_t end = ~0;
    uintptr_t address_end = address + size;
    while (tree) {
        uintptr_t middle = begin + (end - begin) / 2;
        if (address < middle && address_end < middle) {
            end = middle;
            tree = std::static_pointer_cast<Holder>(tree->l);
        }
        else if (address >= middle && address_end >= middle) {
            begin = middle;
            tree = std::static_pointer_cast<Holder>(tree->r);
        }
        else {
            break;
        }
    }
    if (tree) {
        for (uintptr_t i = address; i != address_end; i++) {
            auto [source, byte] = get_value(tree, begin, end, i);
            uintptr_t index = i - address;
            values.bytes[index] = byte;
            values.sources[index] = source;
        }
    }
    return values;
}

Memory::Value Memory::get_value(std::shared_ptr<Holder> tree,
                                uintptr_t begin,
                                uintptr_t end,
                                uintptr_t address) const
{
    std::shared_ptr<void> value = nullptr;
    while (tree) {
        uintptr_t middle = begin + (end - begin) / 2;
        if (address < middle) {
            end = middle;
            if (begin < end - 1) {
                tree = std::static_pointer_cast<Holder>(tree->l);
            }
            else {
                value = tree->l;
                break;
            }
        }
        else if (address >= middle) {
            begin = middle;
            if (begin < end - 1) {
                tree = std::static_pointer_cast<Holder>(tree->r);
            }
            else {
                value = tree->r;
                break;
            }
        }
    }
    if (value) {
        return *std::static_pointer_cast<Value>(value);
    }
    return Value(default_source_);
}
