#pragma once

#include <iosfwd>
#include <map>
#include <string>

namespace rstc {

    class Struc {
    public:
        class Field {
        public:
            friend class Struc;

            enum Type {
                UInt,
                Int,
                Float,
                Pointer,
                Struc,
            };

            enum Signedness : bool {
                Unsigned,
                Signed,
            };

            inline Type type() const { return type_; }
            inline size_t size() const
            {
                return type_ != Struc ? size_ : struc_->get_size();
            }
            inline size_t count() const { return count_; }
            inline class Struc const *struc() const { return struc_; }

            bool is_pointer_alias() const;

            inline bool operator==(Field const &rhs) const
            {
                return type_ == rhs.type_ && size_ == rhs.size_ && count_
                       && rhs.count_ && struc_ == rhs.struc_;
            }

            std::string type_to_string() const;

        private:
            Field(Type type,
                  size_t size,
                  size_t count,
                  class Struc const *struc);

            class Struc const *struc_;
            size_t size_;
            size_t count_;
            Type type_;
        };

        Struc(std::string name);

        void add_int_field(size_t offset,
                           size_t size,
                           Field::Signedness signedness = Field::Unsigned,
                           size_t count = 1);
        void add_float_field(size_t offset, size_t size, size_t count = 1);
        void add_pointer_field(size_t offset,
                               size_t count = 1,
                               Struc const *struc = nullptr);
        void
        add_struc_field(size_t offset, Struc const *struc, size_t count = 1);
        void set_struc_ptr(size_t offset, Struc const *struc);

        inline std::string const &name() const { return name_; }

        size_t get_size() const;
        bool has_field_at_offset(size_t offset);

        inline std::multimap<size_t, Field> const &fields() const
        {
            return fields_;
        }

        static constexpr Struc const *const Atomic = nullptr;

        void print(std::ostream &os) const;

    private:
        bool is_duplicate(size_t offset, Field const &field) const;

        std::string name_;
        std::multimap<size_t, Field> fields_;
    };

}
