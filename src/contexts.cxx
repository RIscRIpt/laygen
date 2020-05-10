#include "contexts.hxx"
#include "utils/adapters.hxx"

using namespace rstc;

void Contexts::remove_multimap_duplicates(
    std::multimap<Address, Context> const &multimap,
    Address value)
{
    Container result;
    auto to_remove = utils::multimap_values(multimap.equal_range(value));
    auto first1 = container_.begin();
    auto last1 = container_.end();
    auto first2 = to_remove.begin();
    auto last2 = to_remove.end();
    while (first1 != last1) {
        if (first2 == last2) {
            break;
        }
        if (*first1 < *first2) {
            if (first1 == container_.begin()) {
                result.emplace(std::move(container_.extract(first1).value()));
                first1 = container_.begin();
            }
            else {
                --first1;
                result.emplace(
                    std::move(container_.extract(std::next(first1)).value()));
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
    if (first1 == container_.begin()) {
        while (!container_.empty()) {
            result.emplace(
                std::move(container_.extract(container_.begin()).value()));
        }
    }
    else {
        while (first1 != last1) {
            --first1;
            result.emplace(
                std::move(container_.extract(std::next(first1)).value()));
            ++first1;
        }
    }
    container_ = std::move(result);
}
