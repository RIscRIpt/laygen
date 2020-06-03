#include "struc.hxx"

#include "utils/adapters.hxx"

#include <algorithm>
#include <cassert>

using namespace rstc;

Struc::Field::Field(Type type,
                    size_t size,
                    size_t count,
                    const class Struc *struc)
    : struc_(struc)
    , size_(size)
    , count_(count)
    , type_(type)
{
}

void Struc::add_int_field(size_t offset, size_t size, size_t count)
{
    // Is 1, 2, 4, 8, 16, 32, 64
    assert(size > 0 && (size & (size - 1)) == 0 && size <= 64);
    fields_.emplace(
        std::piecewise_construct,
        std::forward_as_tuple(offset),
        std::forward_as_tuple(Field(Field::Int, size, count, Atomic)));
}

void Struc::add_float_field(size_t offset, size_t size, size_t count)
{
    assert(size >= 4 && (size & (size - 1)) == 0 && size <= 8);
    fields_.emplace(
        std::piecewise_construct,
        std::forward_as_tuple(offset),
        std::forward_as_tuple(Field(Field::Float, size, count, Atomic)));
}

void Struc::add_pointer_field(size_t offset, size_t count, const Struc *struc)
{
    fields_.emplace(
        std::piecewise_construct,
        std::forward_as_tuple(offset),
        std::forward_as_tuple(Field(Field::Pointer, 8, count, struc)));
}

void Struc::add_struc_field(size_t offset, const Struc *struc, size_t count)
{
    fields_.emplace(
        std::piecewise_construct,
        std::forward_as_tuple(offset),
        std::forward_as_tuple(Field(Field::Struc, 0, count, struc)));
}

size_t Struc::get_size() const
{
    if (fields_.empty()) {
        return 0;
    }
    auto last_offset = fields_.rbegin()->first;
    auto last_fields = utils::multimap_values(fields_.equal_range(last_offset));
    auto largest_last_field = std::max_element(
        last_fields.begin(),
        last_fields.end(),
        [](Field const &a, Field const &b) { return a.size() < b.size(); });
    return last_offset + largest_last_field->size();
}
