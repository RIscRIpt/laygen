#include "memory.hxx"

#include "utils/hash.hxx"

#include <algorithm>

using namespace rstc;
using namespace rstc::virt;

Memory::Values::Values(uintptr_t address, size_t size, Address default_source)
    : address(address)
{
    container.reserve(size);
    uintptr_t id = address;
    intptr_t offset = 0;
    utils::hash::combine(id, offset);
    for (size_t i = 0; i < size; i++) {
        utils::hash::combine(id, address);
        container.push_back(make_symbolic_value(default_source, 1, 0, id));
    }
}

Memory::Values::operator Value() const
{
    assert(container.size() <= 8);
    if (container.size() > 8) {
        return Value();
    }
    bool symbolic = false;
    uintptr_t value = 0;
    uintptr_t id = 0;
    intptr_t offset = 0;
    if (auto const &last = container.back(); last.is_symbolic()) {
        id = last.symbol().id();
        offset = last.symbol().offset();
    }
    auto source = container.front().source();
    for (auto it = container.rbegin(); it != container.rend(); ++it) {
        auto const &byte = *it;
        assert(byte.size() == 1);
        if (!byte.is_symbolic()) {
            assert(!(byte.value() & ~0xFF));
            value <<= 8;
            value |= byte.value();
            utils::hash::reverse(id, byte.value());
        }
        else {
            symbolic = true;
            utils::hash::reverse(id, address);
        }
    }
    if (symbolic) {
        utils::hash::reverse(id, offset);
        return make_symbolic_value(source, container.size(), offset, id);
    }
    return make_value(source, value);
}

Memory::Memory(std::nullptr_t)
    : default_source_(nullptr)
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
    std::vector<Value> values;
    values.reserve(value.size());
    if (!value.is_symbolic()) {
        auto raw_value = value.value();
        std::transform(reinterpret_cast<Byte *>(&raw_value),
                       reinterpret_cast<Byte *>(&raw_value) + value.size(),
                       std::back_inserter(values),
                       [source = value.source()](Byte b) {
                           return make_value(source, b, 1);
                       });
    }
    else {
        uintptr_t id = value.symbol().id();
        utils::hash::combine(id, value.symbol().offset());
        for (size_t i = 0; i < value.size(); i++) {
            utils::hash::combine(id, address);
            values.push_back(make_symbolic_value(value.source(),
                                                 1,
                                                 value.symbol().offset(),
                                                 id));
        }
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
    Values values(address, size, default_source_);
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
