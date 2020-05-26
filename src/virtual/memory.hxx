#pragma once

#include "core.hxx"

#include "registers.hxx"
#include "value.hxx"

#include <map>
#include <vector>

namespace rstc::virt {

    class Memory {
    public:
        struct Values {
            std::vector<Value> container;

            Values(size_t size, Address default_source);

            operator Value() const;
        };

        Memory(std::nullptr_t);
        Memory(Memory const *parent);

        Memory(Memory const &) = delete;
        Memory(Memory &&other) = default;

        Memory &operator=(Memory const &) = delete;
        Memory &operator=(Memory &&rhs) = default;

        void set(uintptr_t address, Value const &value);
        void set(uintptr_t address, std::vector<Value> const &values);
        Values get(uintptr_t address, size_t size) const;

    private:
        struct Holder {
            std::shared_ptr<void> l = nullptr;
            std::shared_ptr<void> r = nullptr;
        };

        void set_value(std::shared_ptr<Holder> tree,
                       std::shared_ptr<Holder> new_tree,
                       uintptr_t begin,
                       uintptr_t end,
                       uintptr_t address,
                       Value const &value);

        Value get_value(std::shared_ptr<Holder> tree,
                        uintptr_t begin,
                        uintptr_t end,
                        uintptr_t address) const;

        Address default_source_;
        std::shared_ptr<void> holder_;
    };

}
