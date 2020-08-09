#pragma once

#include <functional>
#include <iosfwd>
#include <map>
#include <mutex>
#include <set>
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
            inline class Struc *struc()
            {
                return const_cast<class Struc *>(struc_);
            }
            inline class Struc const *struc() const { return struc_; }

            bool is_pointer_alias(size_t) const;
            bool is_float_alias(size_t size) const;
            bool is_typed_int_alias(size_t size) const;

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
            // TODO: Create type priorities table
            Type type_;
        };

        using MergeCallback =
            std::function<void(Struc const &dst, Struc const &src)>;

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
        void merge(Struc const &src, MergeCallback merge_callback);
        bool try_merge_struc_field_at_offset(size_t offset,
                                             Field const &src_field,
                                             MergeCallback merge_callback);
        void merge_fields(size_t offset, Field const &field);

        inline std::string const &name() const { return name_; }

        size_t get_size() const;
        bool has_field_at_offset(size_t offset);

        inline std::multimap<size_t, Field> const &fields() const
        {
            return fields_;
        }

        static constexpr Struc *Atomic = nullptr;

        void print(std::ostream &os) const;

        inline std::recursive_mutex &mutex() const
        {
            return modify_access_mutex_;
        }

    private:
        void add_field(size_t offset, Field field);
        bool is_duplicate(size_t offset, Field const &field) const;
        bool has_aliases(size_t offset,
                         bool (Field::*alias_check)(size_t size) const,
                         size_t size);
        size_t remove_aliases(size_t offset,
                              bool (Field::*alias_check)(size_t size) const,
                              size_t size);

        std::string name_;
        std::multimap<size_t, Field> fields_;
        std::set<size_t> field_set_;

        std::recursive_mutex mutable modify_access_mutex_;
    };

}
