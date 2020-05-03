#pragma once

#include "adapters.hxx"

#include <iterator>
#include <set>
#include <utility>

namespace rstc::utils {

    template<typename K, typename V>
    void
    set_difference_move_multimap_values(std::set<V> &set,
                                        std::multimap<K, V> const &multimap,
                                        K const &value)
    {
        std::set<V> result;
        auto to_remove = multimap_values(multimap.equal_range(value));
        auto first1 = set.begin();
        auto last1 = set.end();
        auto first2 = to_remove.begin();
        auto last2 = to_remove.end();
        while (first1 != last1) {
            if (first2 == last2) {
                break;
            }
            if (*first1 < *first2) {
                if (first1 == set.begin()) {
                    result.emplace(std::move(set.extract(first1).value()));
                    first1 = set.begin();
                }
                else {
                    --first1;
                    result.emplace(
                        std::move(set.extract(std::next(first1)).value()));
                    ++first1;
                }
            }
            else {
                if (!(*first2 < *first1)) {
                    ++first1;
                }
                ++first2;
            }
        }
        if (first1 == set.begin()) {
            while (!set.empty()) {
                result.emplace(std::move(set.extract(set.begin()).value()));
            }
        }
        else {
            while (first1 != last1) {
                --first1;
                result.emplace(
                    std::move(set.extract(std::next(first1)).value()));
                ++first1;
            }
        }
        set = std::move(result);
    }

}
