#pragma once

#include "context.hxx"

#include <set>
#include <unordered_map>

namespace rstc {

    class Contexts {
    public:
        using Container = std::set<Context>;

        using value_type = typename Container::value_type;
        using iterator = typename Container::iterator;
        using const_iterator = typename Container::const_iterator;
        using reverse_iterator = typename Container::reverse_iterator;
        using const_reverse_iterator =
            typename Container::const_reverse_iterator;

        Contexts() = default;

        Contexts(Contexts const &) = delete;
        Contexts(Contexts &&other) = default;

        Contexts &operator=(Contexts const &) = delete;
        Contexts &operator=(Contexts &&rhs) = default;

        inline auto begin() { return container_.begin(); }
        inline auto end() { return container_.end(); }
        inline auto begin() const { return container_.begin(); }
        inline auto end() const { return container_.end(); }
        inline bool empty() const { return container_.empty(); }
        inline auto size() const { return container_.size(); }
        inline auto pop()
        {
            auto result = std::move(
                container_.extract(std::prev(container_.end())).value());
            return result;
        }
        inline auto insert(iterator where, Context &&context)
        {
            auto it = container_.insert(where, std::move(context));
            return it;
        }
        inline auto insert(Context &&context)
        {
            auto [it, inserted] = container_.insert(std::move(context));
            return std::make_pair(it, inserted);
        }
        inline auto emplace(Context &&context)
        {
            return insert(std::move(context));
        }
        inline void merge(Contexts &&contexts)
        {
            container_.merge(std::move(contexts.container_));
        }

    private:
        Container container_;
    };

}
