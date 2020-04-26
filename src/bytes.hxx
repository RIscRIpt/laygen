#pragma once

#include "core.hxx"

#include <cstdint>
#include <filesystem>
#include <vector>

namespace rstc {

    class Bytes {
    public:
        using Container = std::vector<Byte>;

        Bytes(std::filesystem::path const &path);

        Container::value_type const *data() const;

    private:
        Container bytes_;
    };

}
