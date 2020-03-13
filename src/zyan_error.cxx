#include "zyan_error.hxx"

#include <sstream>

using namespace rstc;

zyan_error::zyan_error(ZyanStatus status)
    : std::runtime_error(error_from_status(status))
{
}

std::string zyan_error::error_from_status(ZyanStatus status)
{
    std::ostringstream oss;
    oss << "Zydis failed with status: " << status;
    return oss.str();
}
