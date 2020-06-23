#pragma once

#include "core.hxx"

#include <atomic>
#include <compare>
#include <optional>
#include <variant>

namespace rstc::virt {

    class Value {
    public:
        class Symbol {
        public:
            explicit Symbol(uintptr_t id = 0, intptr_t offset = 0);

            inline uintptr_t id() const { return id_; }
            inline intptr_t offset() const { return offset_; }

        private:
            uintptr_t id_;
            intptr_t offset_;
            static std::atomic<uintptr_t> next_id_;
        };

        using ValueContainer = std::variant<uintptr_t, Symbol>;

        explicit Value(Address source = nullptr,
                       ValueContainer value = Symbol(),
                       int size = 8);

        inline bool is_symbolic() const
        {
            return std::holds_alternative<Symbol>(value_);
        }

        inline Address source() const { return source_; }
        inline uintptr_t value() const { return std::get<uintptr_t>(value_); }
        inline Symbol symbol() const { return std::get<Symbol>(value_); }
        inline int size() const { return size_; }

        inline void set_source(Address source) { source_ = source; }
        inline void set_size(int size) { size_ = size; }

        inline uintptr_t raw_value() const
        {
            if (is_symbolic()) {
                auto const &s = symbol();
                return (s.id() << 32) | (s.offset() & 0xFFFFFFFF);
            }
            return value();
        }

        inline uintptr_t raw_address_value() const
        {
            if (is_symbolic()) {
                return symbol().id();
            }
            return value();
        }

        inline auto operator<=>(Value const &rhs) const
        {
            return raw_value() <=> rhs.raw_value();
        }

        // For std::equal_to, for std::unordered_map
        inline bool operator==(Value const &rhs) const
        {
            return raw_value() == rhs.raw_value();
        }

    private:
        Address source_;
        ValueContainer value_;
        int size_;
    };

    Value make_value(Address source, uintptr_t value, int size = 8);
    Value make_symbolic_value(Address source,
                              int size = 8,
                              intptr_t offset = 0,
                              uintptr_t id = 0);

}

namespace std {
    template<>
    struct hash<rstc::virt::Value> {
        size_t operator()(rstc::virt::Value const &value) const
        {
            return value.raw_value();
        }
    };
}
