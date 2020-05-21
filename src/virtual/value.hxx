#pragma once

#include "core.hxx"

#include <random>
#include <optional>
#include <variant>

namespace rstc::virt {

    class Value {
    public:
        class Symbol {
        public:
            Symbol();
            explicit Symbol(uintptr_t id);
            inline bool operator==(Symbol const &rhs) const
            {
                return id_ == rhs.id_;
            }
            inline bool operator!=(Symbol const &rhs) const
            {
                return id_ != rhs.id_;
            }
            inline uintptr_t id() const { return id_; }

        private:
            uintptr_t id_;
            static std::mt19937_64 id_generator;
            static std::uniform_int_distribution<uintptr_t> id_distribution;
        };

        using ValueContainer = std::variant<uintptr_t, Symbol>;

        explicit Value(Address source = nullptr,
                       ValueContainer value = Symbol(),
                       int size = 8);

        /*
        Value(Value const &other);
        Value(Value &&other);

        Value &operator=(Value const &rhs);
        Value &operator=(Value &&rhs) noexcept;

        void swap(Value &a, Value &b);
        */

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

    private:
        Address source_;
        ValueContainer value_;
        int size_;
    };

    Value make_value(Address source, uintptr_t value, int size = 8);
    Value make_symbolic_value(Address source, int size = 8);
    Value make_symbolic_value(Address source, uintptr_t id, int size = 8);
}
