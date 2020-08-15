#pragma once

#include <utility>

namespace rstc::utils {

    template<typename I>
    struct PairRangeAdapter {
        std::pair<I, I> pair;
        PairRangeAdapter(std::pair<I, I> const &pair)
            : pair(pair)
        {
        }
        inline I begin() const { return pair.first; }
        inline I end() const { return pair.second; }
        inline bool empty() const { return pair.first == pair.second; }
    };

    template<typename I>
    inline auto in_range(std::pair<I, I> const &pair)
    {
        return PairRangeAdapter<I>(pair);
    }

    template<template<typename...> typename M, typename K, typename V>
    class MultimapValuesIterator {
    public:
        using underlying_iterator = typename M<K, V>::const_iterator;
        using value_type = V;
        using difference_type = typename underlying_iterator::difference_type;
        using pointer = typename underlying_iterator::pointer;
        using reference = typename underlying_iterator::reference;
        using iterator_category =
            typename underlying_iterator::iterator_category;

        explicit MultimapValuesIterator(underlying_iterator iterator)
            : iterator_(iterator)
        {
        }
        value_type const &operator*() const { return iterator_->second; }
        value_type const *operator->() { return &iterator_->second; }
        bool operator==(MultimapValuesIterator<M, K, V> const &rhs) const
        {
            return iterator_ == rhs.iterator_;
        }
        bool operator!=(MultimapValuesIterator<M, K, V> const &rhs) const
        {
            return !(*this == rhs);
        }
        MultimapValuesIterator<M, K, V> operator++(int)
        {
            return MultimapValuesIterator(++iterator_);
        }
        MultimapValuesIterator<M, K, V> &operator++()
        {
            ++iterator_;
            return *this;
        }
        MultimapValuesIterator<M, K, V> operator--(int)
        {
            return MultimapValuesIterator(--iterator_);
        }
        MultimapValuesIterator<M, K, V> &operator--()
        {
            --iterator_;
            return *this;
        }

    private:
        underlying_iterator iterator_;
    };

    template<template<typename...> typename M, typename K, typename V>
    inline auto multimap_values(M<K, V> const &m, K const &k)
    {
        using I = MultimapValuesIterator<M, K, V>;
        auto range = m.equal_range(k);
        return PairRangeAdapter<I>(std::pair<I, I>(range.first, range.second));
    }

}
