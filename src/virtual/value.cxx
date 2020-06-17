#include "value.hxx"

using namespace rstc;
using namespace rstc::virt;

std::atomic<uintptr_t> Value::Symbol::next_id_ = 1;

Value::Symbol::Symbol(uintptr_t id, intptr_t offset)
    : id_(next_id_++)
    , offset_(offset)
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

Value rstc::virt::make_symbolic_value(Address source,
                                      int size,
                                      intptr_t offset,
                                      uintptr_t id)
{
    return Value(source, Value::Symbol(id, offset), size);
}
