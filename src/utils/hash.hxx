#pragma once

#include <functional>

namespace rstc::utils::hash {

    template<class T>
    static inline void combine(std::size_t &seed, const T &v)
    {
        std::hash<T> hasher;
        seed *= 0x5851F42D4C957F2D;
        seed ^= hasher(v);
        seed += 0x14057B7EF767814F;
    }

    template<class T>
    static inline void reverse(std::size_t &seed, const T &v)
    {
        std::hash<T> hasher;
        seed -= 0x14057B7EF767814F;
        seed ^= hasher(v);
        seed *= 0xC097EF87329E28A5; // 0x5851F42D4C957F2D^-1 MOD 2^64
    }

}
