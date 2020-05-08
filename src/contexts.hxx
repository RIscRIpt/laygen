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

        void remove_multimap_duplicates(
            std::multimap<Address, Context> const &multimap,
            Address const &value);

        inline auto begin() { return container_.begin(); }
        inline auto end() { return container_.end(); }
        inline auto begin() const { return container_.begin(); }
        inline auto end() const { return container_.end(); }
        inline bool empty() const { return container_.empty(); }
        inline auto size() const { return container_.size(); }
        inline auto pop()
        {
            return std::move(
                container_.extract(std::prev(container_.end())).value());
        }
        inline auto insert(iterator where, Context &&context)
        {
            auto it = container_.insert(where, std::move(context));
            context_by_id_.insert_or_assign(it->get_id(), &*it);
            return it;
        }
        inline auto insert(Context &&context)
        {
            auto [it, inserted] = container_.insert(std::move(context));
            if (inserted) {
                context_by_id_.insert_or_assign(it->get_id(), &*it);
            }
            return std::make_pair(it, inserted);
        }
        inline auto emplace(Context &&context) { return insert(std::move(context)); }
        inline void merge(Contexts &&contexts)
        {
            container_.merge(std::move(contexts.container_));
            context_by_id_.clear();
            for (auto const &context : container_) {
                context_by_id_.insert_or_assign(context.get_id(), &context);
            }
        }

        inline Context const *get_context_by_id(size_t id) const
        {
            if (auto it = context_by_id_.find(id); it != context_by_id_.end()) {
                return it->second;
            }
            return nullptr;
        }

    private:
        Container container_;
        std::unordered_map<size_t, Context const *> context_by_id_;
    };

}
