#pragma once

#include "core.hxx"

#include "registers.hxx"

#include <map>
#include <vector>

namespace rstc::virt {

    class Memory {
    public:
        struct Value {
            Address source;
            Byte byte;

            Value(Address source, Byte byte = 0);
        };

        struct Values {
            std::vector<Byte> bytes;
            std::vector<Address> sources;

            Values(size_t size, Address default_source);

            operator Registers::Value() const;
        };

        Memory(Address source);
        Memory(Memory const *parent);

        Memory(Memory const &) = delete;
        Memory(Memory &&other) = default;

        Memory &operator=(Memory const &) = delete;
        Memory &operator=(Memory &&rhs) = default;

        void set(uintptr_t address,
                 Address source,
                 Registers::Value value,
                 size_t size);
        void
        set(uintptr_t address, Address source, std::vector<Byte> const &bytes);
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
                       Address source,
                       Byte byte);

        Value get_value(std::shared_ptr<Holder> tree,
                        uintptr_t begin,
                        uintptr_t end,
                        uintptr_t address) const;

        Address default_source_;
        std::shared_ptr<void> holder_;
    };

}
