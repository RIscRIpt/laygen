#pragma once

#include <map>

namespace rstc {

    class Struc {
    public:
        class Field {
        public:
            friend class Struc;

            enum Type {
                Int,
                Float,
                Pointer,
                Struc,
            };

            inline Type type() const { return type_; }
            inline size_t size() const
            {
                return type_ != Struc ? size_ : struc_->get_size();
            }
            inline size_t count() const { return count_; }
            inline const class Struc *struc() const { return struc_; }

        private:
            Field(Type type,
                  size_t size,
                  size_t count,
                  const class Struc *struc);

            const class Struc *struc_;
            size_t size_;
            size_t count_;
            Type type_;
        };

        void add_int_field(size_t offset, size_t size, size_t count = 1);
        void add_float_field(size_t offset, size_t size, size_t count = 1);
        void add_pointer_field(size_t offset,
                               size_t count = 1,
                               const Struc *struc = nullptr);
        void
        add_struc_field(size_t offset, const Struc *struc, size_t count = 1);

        size_t get_size() const;

        inline std::multimap<size_t, Field> const &fields() const
        {
            return fields_;
        }

        static constexpr const Struc *const Atomic = nullptr;

    private:
        std::multimap<size_t, Field> fields_;
    };

}
