#pragma once

#include <map>

namespace rstc::utils {

    template<typename I>
    struct PairRangeAdapter {
        std::pair<I, I> pair;
        PairRangeAdapter(std::pair<I, I> const &pair)
            : pair(pair)
        {
        }
        I begin() const { return pair.first; }
        I end() const { return pair.second; }
    };

    template<typename I>
    inline auto in_range(std::pair<I, I> const &pair)
    {
        return PairRangeAdapter<I>(pair);
    }

    template<typename K, typename V>
    class MultimapValuesIterator {
    public:
        using underlying_iterator =
            typename std::multimap<K, V>::const_iterator;
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
        bool operator==(MultimapValuesIterator<K, V> const &rhs) const
        {
            return iterator_ == rhs.iterator_;
        }
        bool operator!=(MultimapValuesIterator<K, V> const &rhs) const
        {
            return !(*this == rhs);
        }
        MultimapValuesIterator<K, V> operator++(int)
        {
            return MultimapValuesIterator(++iterator_);
        }
        MultimapValuesIterator<K, V> &operator++()
        {
            ++iterator_;
            return *this;
        }
        MultimapValuesIterator<K, V> operator--(int)
        {
            return MultimapValuesIterator(--iterator_);
        }
        MultimapValuesIterator<K, V> &operator--()
        {
            --iterator_;
            return *this;
        }

    private:
        underlying_iterator iterator_;
    };

    template<typename I>
    inline auto multimap_values(std::pair<I, I> const &pair)
    {
        using mm_type = typename I::value_type;
        using values_iterator =
            MultimapValuesIterator<typename mm_type::first_type,
                                   typename mm_type::second_type>;
        return PairRangeAdapter<values_iterator>(
            std::pair<values_iterator, values_iterator>(pair.first,
                                                        pair.second));
    }

}
