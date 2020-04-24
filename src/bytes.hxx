#pragma once

#include <cstdint>
#include <filesystem>
#include <vector>

namespace rstc {

    class Bytes {
    public:
        using Container = std::vector<unsigned char>;

        Bytes(std::filesystem::path const &path);

        Container::value_type const *data() const;

    private:
        Container bytes_;
    };

}
