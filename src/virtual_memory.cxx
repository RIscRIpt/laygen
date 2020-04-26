#include "virtual_memory.hxx"

#include <algorithm>

using namespace rstc;

VirtualMemory::VirtualMemory()
{
    memory_map_.emplace(0, std::vector<Byte>{});
    source_map_.emplace(0, nullptr);
}

void VirtualMemory::assign(uintptr_t address,
                           std::vector<Byte> memory,
                           Address source)
{
    assign_source(address, memory.size(), source);
    assign_memory(address, std::move(memory));
}

VirtualMemory::MemoryWithSources VirtualMemory::get(uintptr_t address,
                                                    size_t size) const
{
    auto memory = get_memory(address, size);
    auto sources = get_sources(address, size);
    return { memory, sources };
}

void VirtualMemory::assign_memory(uintptr_t address, std::vector<Byte> memory)
{
    auto key_begin = address;
    auto key_end = address + memory.size();
    if (!(key_begin < key_end)) {
        return;
    }
    auto erase_begin = memory_map_.upper_bound(key_begin);
    auto erase_end = memory_map_.upper_bound(key_end);
    auto interval_begin = std::prev(erase_begin);
    auto interval_end = std::prev(erase_end);
    if (!(interval_begin->first < key_begin)
        && interval_begin != memory_map_.begin()) {
        interval_begin = std::prev(interval_begin);
        erase_begin = std::prev(erase_begin);
    }
    bool merge_tail =
        !(interval_end->first + interval_end->second.size() < key_end);
    std::vector<Byte> tail;
    size_t new_tail_size;
    if (merge_tail) {
        tail = std::move(interval_end->second);
        new_tail_size = interval_end->first + tail.size() - key_end;
    }
    memory_map_.erase(erase_begin, erase_end);
    if (!(interval_begin->first + interval_begin->second.size() < key_begin)) {
        auto head_address = interval_begin->first;
        auto &head = interval_begin->second;
        size_t new_size = key_begin - head_address + memory.size();
        if (merge_tail) {
            new_size += new_tail_size;
        }
        if (head.size() < new_size) {
            head.resize(new_size);
        }
        size_t memory_insert_offset = key_begin - head_address;
        std::copy(memory.begin(),
                  memory.end(),
                  head.begin() + memory_insert_offset);
        if (merge_tail) {
            std::copy(tail.begin() + (tail.size() - new_tail_size),
                      tail.end(),
                      head.begin() + memory_insert_offset + memory.size());
        }
    }
    else {
        if (merge_tail) {
            size_t tail_insert_pos = memory.size();
            memory.resize(memory.size() + new_tail_size);
            std::copy(tail.begin() + (tail.size() - new_tail_size),
                      tail.end(),
                      memory.begin() + tail_insert_pos);
        }
        memory_map_.insert_or_assign(key_begin, std::move(memory));
    }
}

void VirtualMemory::assign_source(uintptr_t address,
                                  size_t size,
                                  Address source)
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

VirtualMemory::Memory VirtualMemory::get_memory(uintptr_t address,
                                            size_t size) const
{
    auto it = std::prev(memory_map_.upper_bound(address));
    size_t offset = address - it->first;
    std::vector<Byte> result;
    if (offset < it->second.size()) {
        result.resize(std::min(it->second.size() - offset, size));
        std::copy(it->second.begin() + offset,
                  it->second.begin() + offset + result.size(),
                  result.begin());
        return { 0, result };
    }
    else {
        ++it;
        if (!(it->first < address + size)) {
            return {};
        }
        offset = it->first - address;
        result.resize(address + size - it->first);
        std::copy(it->second.begin(),
                  it->second.begin() + result.size(),
                  result.begin());
        return { offset, result };
    }
}

std::vector<VirtualMemory::Source> VirtualMemory::get_sources(uintptr_t address,
                                                              size_t size) const
{
    auto source_next = source_map_.upper_bound(address);
    auto source_begin = std::prev(source_next);
    auto source_end = std::prev(source_map_.upper_bound(address + size));
    std::vector<Source> sources(std::distance(source_begin, source_end) + 1);
    for (size_t i = 0; i < sources.size(); i++) {
        sources[i] = Source(source_begin->first,
                            source_next->first,
                            source_begin->second);
        ++source_begin;
        ++source_next;
    }
    return std::move(sources);
}
