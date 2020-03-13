#pragma once

#include <Zycore/Status.h>

#include <stdexcept>
#include <string>

namespace rstc {

    class zyan_error : public std::runtime_error {
    public:
        zyan_error(ZyanStatus status);

    private:
        static std::string error_from_status(ZyanStatus status);
    };

}
