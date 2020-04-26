#pragma once

#include "core.hxx"

#include <map>
#include <vector>

namespace rstc {

    class VirtualMemory {
    public:
        struct Source {
            Source() = default;
            Source(uintptr_t start, uintptr_t end, Address source)
                : start(start)
                , end(end)
                , source(source)
            {
            }
            uintptr_t start = 0;
            uintptr_t end = 0;
            Address source = nullptr;
        };

        struct Memory {
            size_t offset;
            std::vector<Byte> memory;
        };

        struct MemoryWithSources : Memory {
            std::vector<Source> sources;
        };

        VirtualMemory();

        void
        assign(uintptr_t address, std::vector<Byte> memory, Address source);
        MemoryWithSources get(uintptr_t address, size_t size) const;

    private:
        void assign_memory(uintptr_t address, std::vector<Byte> memory);
        void assign_source(uintptr_t address, size_t size, Address source);

        Memory get_memory(uintptr_t address, size_t size) const;
        std::vector<Source> get_sources(uintptr_t address, size_t size) const;

        std::map<uintptr_t, std::vector<Byte>> memory_map_;
        std::map<uintptr_t, Address> source_map_;
    };

}
