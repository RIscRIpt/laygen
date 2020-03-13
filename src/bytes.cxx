#include "bytes.hxx"

#include <fstream>
#include <iterator>

using namespace rstc;

Bytes::Bytes(std::filesystem::path const &path)
{
    std::ifstream file;
    file.exceptions(std::ios::badbit | std::ios::failbit);
    file.open(path, std::ios::binary);
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    bytes_.resize(size);
    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char *>(bytes_.data()), bytes_.size());
}

Bytes::Container::value_type *Bytes::data()
{
    return bytes_.data();
}
