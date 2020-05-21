#pragma once

#include <functional>

namespace rstc::utils {

    template<class T>
    static inline void hash_combine(std::size_t &seed, const T &v)
    {
        std::hash<T> hasher;
        seed ^= hasher(v) * 0x5851F42D4C957F2D + 0x14057B7EF767814F;
    }

}
