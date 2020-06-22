#pragma once

#include <functional>

namespace rstc::utils::hash {

    // Order-dependent combination
    // Use `reverse` to un-hash `v`.
    template<class T>
    inline void combine(std::size_t &seed, const T &v)
    {
        std::hash<T> hasher;
        seed *= 0x5851F42D4C957F2D;
        seed ^= hasher(v);
        seed += 0x14057B7EF767814F;
    }

    template<class T>
    inline void reverse(std::size_t &seed, const T &v)
    {
        std::hash<T> hasher;
        seed -= 0x14057B7EF767814F;
        seed ^= hasher(v);
        seed *= 0xC097EF87329E28A5; // 0x5851F42D4C957F2D^-1 MOD 2^64
    }

    // Order-independent combination
    // Use `mix` to hash and un-hash `v`.
    template<class T>
    inline void mix(std::size_t &seed, const T &v)
    {
        std::hash<T> hasher;
        seed ^= hasher(v) * 0x5851F42D4C957F2D + 0x14057B7EF767814F;
    }

}
