#include "memory.hxx"

#include "utils/hash.hxx"

#include <algorithm>

using namespace rstc;
using namespace rstc::virt;

Memory::Values::Values(size_t size, Address default_source)
{
    container.reserve(size);
    for (size_t i = 0; i < size; i++) {
        container.emplace_back(make_symbolic_value(default_source, 1));
    }
}

Memory::Values::operator Value() const
{
    if (container.size() > 8) {
        return Value();
    }
    bool symbolic = false;
    uintptr_t value = 0;
    uintptr_t id = 0;
    for (auto const &byte : container) {
        assert(byte.size() == 1);
        if (!byte.is_symbolic()) {
            assert(!(byte.value() & ~0xFF));
            value <<= 8;
            value |= byte.value();
            utils::hash_combine(id, byte.value());
        }
        else {
            symbolic = true;
            id ^= byte.symbol().id();
        }
    }
    if (symbolic) {
        return make_symbolic_value(container.front().source(),
                                   id,
                                   container.size());
    }
    return make_value(container.front().source(), value);
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

void Memory::set(uintptr_t address, Value const &value)
{
    std::vector<Value> values(value.size());
    if (!value.is_symbolic()) {
        auto raw_value = value.value();
        std::transform(reinterpret_cast<Byte *>(&raw_value),
                       reinterpret_cast<Byte *>(&raw_value) + value.size(),
                       values.begin(),
                       [source = value.source()](Byte b) {
                           return make_value(source, b, 1);
                       });
    }
    else {
        uintptr_t first_symbol_id = value.symbol().id();
        for (size_t i = 1; i < value.size(); i++) {
            values[i] = make_symbolic_value(value.source(), 1);
            first_symbol_id ^= values[i].symbol().id();
        }
        values[0] = make_symbolic_value(value.source(), first_symbol_id, 1);
    }
    set(address, values);
}

void Memory::set(uintptr_t address, std::vector<Value> const &values)
{
    if (values.empty()) {
        return;
    }
    auto tree = std::static_pointer_cast<Holder>(holder_);
    auto new_tree = std::make_shared<Holder>();
    holder_ = new_tree;
    uintptr_t begin = 0;
    uintptr_t end = ~0;
    uintptr_t address_end = address + values.size();
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
        auto const &value = values[i - address];
        set_value(tree, new_tree, begin, end, i, value);
        tree = new_tree;
    }
}

void Memory::set_value(std::shared_ptr<Holder> tree,
                       std::shared_ptr<Holder> new_tree,
                       uintptr_t begin,
                       uintptr_t end,
                       uintptr_t address,
                       Value const &value)
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
                new_tree->l = std::make_shared<Value>(value);
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
                new_tree->r = std::make_shared<Value>(value);
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
            values.container[i - address] = get_value(tree, begin, end, i);
        }
    }
    return values;
}

Value Memory::get_value(std::shared_ptr<Holder> tree,
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
    return make_symbolic_value(default_source_, 1);
}
