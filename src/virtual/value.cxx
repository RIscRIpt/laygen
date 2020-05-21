#include "value.hxx"

using namespace rstc;
using namespace rstc::virt;

std::mt19937_64 Value::Symbol::id_generator;
std::uniform_int_distribution<uintptr_t> Value::Symbol::id_distribution;

Value::Symbol::Symbol()
    : id_(id_distribution(id_generator))
{
}

Value::Symbol::Symbol(uintptr_t id)
    : id_(id)
{
}

Value::Value(Address source, ValueContainer value, int size)
    : source_(source)
    , value_(std::move(value))
    , size_(size)
{
}

Value rstc::virt::make_value(Address source, uintptr_t value, int size)
{
    return Value(source, value, size);
}

Value rstc::virt::make_symbolic_value(Address source, int size)
{
    return Value(source, Value::Symbol(), size);
}

Value rstc::virt::make_symbolic_value(Address source, uintptr_t id, int size)
{
    return Value(source, Value::Symbol(id), size);
}
