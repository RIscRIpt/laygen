#pragma once

#include <type_traits>
#include <utility>

namespace rstc {

    template<typename Callback>
    class ScopeGuard final {
    public:
        ScopeGuard(Callback &&callback)
            : callback_(std::forward<Callback>(callback))
            , active_(true)
        {
        }

        ~ScopeGuard()
        {
            if (active_) {
                callback_();
            }
        }

        ScopeGuard(ScopeGuard const &) = delete;
        ScopeGuard(ScopeGuard &&) = delete;
        ScopeGuard &operator=(ScopeGuard const &) = delete;
        ScopeGuard &operator=(ScopeGuard &&) = delete;

    private:
        Callback callback_;
        bool active_;
    };

}