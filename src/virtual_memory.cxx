#include "virtual_memory.hxx"

#include <algorithm>

using namespace rstc;

VirtualMemory::VirtualMemory(Address source)
{
    source_map_.emplace(0, source);
}

void VirtualMemory::assign(uintptr_t address, size_t size, Address source)
{
    auto key_begin = address;
    auto key_end = address + size;
    if (!(key_begin < key_end)) {
        return;
    }
    auto erase_begin = source_map_.upper_bound(key_begin);
    auto erase_end = source_map_.upper_bound(key_end);
    auto interval_begin = std::prev(erase_begin);
    auto interval_end = std::prev(erase_end);
    if (!(interval_begin->first < key_begin)
        && interval_begin != source_map_.begin()) {
        interval_begin = std::prev(interval_begin);
        erase_begin = std::prev(erase_begin);
    }
    bool assign_first = !(interval_begin->second == source);
    bool keep_tail = !(interval_end->second == source);
    auto const tail = interval_end->second;
    source_map_.erase(erase_begin, erase_end);
    if (assign_first) {
        source_map_.insert_or_assign(key_begin, source);
    }
    if (keep_tail) {
        source_map_.insert_or_assign(key_end, tail);
    }
}

VirtualMemory::Sources VirtualMemory::get(uintptr_t address, size_t size) const
{
    auto source_next = source_map_.upper_bound(address);
    auto source_begin = std::prev(source_next);
    auto source_end = std::prev(source_map_.upper_bound(address + size));
    size_t count = std::distance(source_begin, source_end);
    if (source_end->first < address + size) {
        count++;
    }
    std::vector<Source> sources(count);
    for (size_t i = 0; i < sources.size(); i++) {
        uintptr_t begin = source_begin->first;
        uintptr_t end;
        if (source_next != source_map_.end()) {
            end = source_next->first;
        }
        else {
            end = address + size;
        }
        sources[i] = Source(source_begin->second, begin, end);
        if (i + 1 < sources.size()) {
            ++source_begin;
            ++source_next;
        }
    }
    return std::move(sources);
}

VirtualMemory::Sources VirtualMemory::get_all() const
{
    return std::move(get(0, source_map_.rbegin()->first));
}

Address VirtualMemory::get_root_source() const
{
    return source_map_.begin()->second;
}
