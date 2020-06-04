#include "struc.hxx"

#include "utils/adapters.hxx"

#include <algorithm>
#include <cassert>
#include <iomanip>
#include <iostream>

using namespace rstc;

Struc::Field::Field(Type type,
                    size_t size,
                    size_t count,
                    class Struc const *struc)
    : struc_(struc)
    , size_(size)
    , count_(count)
    , type_(type)
{
}

Struc::Struc(std::string name)
    : name_(std::move(name))
{
}

void Struc::add_int_field(size_t offset,
                          size_t size,
                          Field::Signedness signedness,
                          size_t count)
{
    // Is 1, 2, 4, 8, 16, 32, 64
    assert(size > 0 && (size & (size - 1)) == 0 && size <= 64);
    Field field(signedness == Field::Unsigned ? Field::UInt : Field::Int,
                size,
                count,
                Atomic);
    if (!is_duplicate(offset, field)) {
        fields_.emplace(offset, std::move(field));
    }
}

void Struc::add_float_field(size_t offset, size_t size, size_t count)
{
    assert(size == 2 || size == 4 || size == 8 || size == 10);
    Field field(Field::Float, size, count, Atomic);
    if (!is_duplicate(offset, field)) {
        fields_.emplace(offset, std::move(field));
    }
}

void Struc::add_pointer_field(size_t offset, size_t count, Struc const *struc)
{
    Field field(Field::Pointer, 8, count, struc);
    if (!is_duplicate(offset, field)) {
        fields_.emplace(offset, std::move(field));
    }
}

void Struc::add_struc_field(size_t offset, Struc const *struc, size_t count)
{
    Field field(Field::Struc, 0, count, struc);
    if (!is_duplicate(offset, field)) {
        fields_.emplace(offset, std::move(field));
    }
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

bool Struc::is_duplicate(size_t offset, Field const &field) const
{
    auto other_fields = utils::multimap_values(fields_.equal_range(offset));
    auto it = std::find(other_fields.begin(), other_fields.end(), field);
    return it != other_fields.end();
}

static std::string field_type_to_string(Struc::Field const &field)
{
    switch (field.type()) {
    case Struc::Field::UInt:
        switch (field.size()) {
        case 1: return "uint8_t";
        case 2: return "uint16_t";
        case 4: return "uint32_t";
        case 8: return "uint64_t";
        }
        break;
    case Struc::Field::Int:
        switch (field.size()) {
        case 1: return "int8_t";
        case 2: return "int16_t";
        case 4: return "int32_t";
        case 8: return "int64_t";
        }
        break;
    case Struc::Field::Float:
        switch (field.size()) {
        case 2: return "f16_t";
        case 4: return "float";
        case 8: return "double";
        case 10: return "long double";
        }
        break;
    case Struc::Field::Pointer:
        if (field.struc()) {
            return field.struc()->name() + "*";
        }
        else {
            return "void*";
        }
        break;
    case Struc::Field::Struc: return field.struc()->name().c_str(); break;
    }
    return "";
}

void rstc::print_struc(std::ostream &os, Struc const &struc)
{
    auto os_flags = os.flags();
    os << std::setfill('0');
    os << "struct " << struc.name() << " {\n";
    auto fields = struc.fields();
    size_t next_offset = 0;
    for (auto it = fields.begin(); it != fields.end();) {
        auto base_offset = it->first;
        if (base_offset > next_offset) {
            os << "    char _padding_" << std::hex << std::setw(4)
               << next_offset << "[0x" << std::hex << std::setw(4)
               << base_offset - next_offset << "];\n";
        }
        size_t union_field_count = 1;
        next_offset = base_offset + it->second.size() * it->second.count();
        auto it_end = std::next(it);
        while (it_end != fields.end()) {
            auto prev = std::prev(it_end);
            auto offset =
                prev->first + prev->second.size() * prev->second.count();
            if (offset <= it_end->first) {
                break;
            }
            if (next_offset < offset) {
                next_offset = offset;
            }
            ++it_end;
            union_field_count++;
        }
        bool is_union = union_field_count > 1;
        std::string indent = "    ";
        if (is_union) {
            os << "    union {\n";
            indent += "    ";
        }
        for (size_t j = 1; j <= union_field_count; j++, ++it) {
            auto offset = it->first;
            auto const &field = it->second;
            if (offset == base_offset) {
                os << indent << field_type_to_string(field) << ' ' << "field_"
                   << std::hex << std::setw(4) << offset;
                if (is_union) {
                    os << "_" << std::dec << j;
                }
                if (field.count() > 1) {
                    os << '[' << std::dec << field.count() << ']';
                }
            }
            else {
                os << indent << "struct { char _padding[0x" << std::hex
                   << std::setw(4) << offset - base_offset << "]; "
                   << field_type_to_string(field) << " value";
                if (field.count() > 1) {
                    os << '[' << std::dec << field.count() << ']';
                }
                os << "; } field_" << std::hex << std::setw(4) << offset;
                if (is_union) {
                    os << "_" << std::dec << j;
                }
            }
            os << ";\n";
        }
        if (is_union) {
            os << "    };\n";
        }
    }
    os << "};\n";
    os.flags(os_flags);
}
