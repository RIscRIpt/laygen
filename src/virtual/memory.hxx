#pragma once

#include "core.hxx"

#include <map>
#include <vector>

namespace rstc::virt {

    class Memory {
    public:
        struct Source {
            Source() = default;
            Source(Address source, uintptr_t start, uintptr_t end)
                : source(source)
                , start(start)
                , end(end)
            {
            }
            Address source = nullptr;
            uintptr_t start = 0;
            uintptr_t end = 0;
        };
        using Sources = std::vector<Source>;

        Memory(Address source);

        void assign(uintptr_t address, size_t size, Address source);
        Sources get(uintptr_t address, size_t size) const;
        Sources get_all() const;

        Address get_root_source() const;

    private:
        std::map<uintptr_t, Address> source_map_;
    };

}
