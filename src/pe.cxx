#include "pe.hxx"

#include <fstream>

using namespace rstc;

PE::PE(std::filesystem::path const &path)
    : bytes_(Bytes(path))
{
    auto file_header = image_file_header();
    if (file_header->Machine != IMAGE_FILE_MACHINE_AMD64) {
        throw std::runtime_error("unsupported architecture");
    }
    auto first_section = image_first_section();
    sections_by_va_ = std::vector<IMAGE_SECTION_HEADER const *>(
        file_header->NumberOfSections);
    sections_by_raw_data_ = std::vector<IMAGE_SECTION_HEADER const *>(
        file_header->NumberOfSections);
    for (size_t i = 0; i < file_header->NumberOfSections; i++) {
        sections_by_va_[i] = &first_section[i];
        sections_by_raw_data_[i] = &first_section[i];
    }
    std::sort(sections_by_va_.begin(),
              sections_by_va_.end(),
              [](IMAGE_SECTION_HEADER const *a, IMAGE_SECTION_HEADER const *b) {
                  return a->VirtualAddress < b->VirtualAddress;
              });
    std::sort(sections_by_raw_data_.begin(),
              sections_by_raw_data_.end(),
              [](IMAGE_SECTION_HEADER const *a, IMAGE_SECTION_HEADER const *b) {
                  return a->PointerToRawData < b->PointerToRawData;
              });
    for (auto const &runtime_function : runtime_functions()) {
        runtime_function_map_.emplace(runtime_function.BeginAddress,
                                      &runtime_function);
    }
}

Byte const *PE::data() const
{
    return bytes_.data();
}

IMAGE_DOS_HEADER const *PE::image_dos_header() const
{
    return reinterpret_cast<IMAGE_DOS_HEADER const *>(data());
}

IMAGE_NT_HEADERS const *PE::image_nt_headers() const
{
    return reinterpret_cast<IMAGE_NT_HEADERS const *>(
        data() + image_dos_header()->e_lfanew);
}

IMAGE_SECTION_HEADER const *PE::image_first_section() const
{
    return IMAGE_FIRST_SECTION(image_nt_headers());
}

IMAGE_SECTION_HEADER const *
PE::get_section_by_raw_address(Byte const *pointer) const
{
    auto it = std::upper_bound(
        sections_by_raw_data_.begin(),
        sections_by_raw_data_.end(),
        static_cast<DWORD>(pointer - data()),
        [](DWORD raw_address, IMAGE_SECTION_HEADER const *section) {
            return raw_address < section->PointerToRawData;
        });
    if (it == sections_by_raw_data_.begin()) {
        throw std::runtime_error("invalid raw address");
    }
    return *std::prev(it);
}

IMAGE_FILE_HEADER const *PE::image_file_header() const
{
    return &image_nt_headers()->FileHeader;
}

IMAGE_OPTIONAL_HEADER64 const *PE::image_optional_header64() const
{
    return &reinterpret_cast<IMAGE_NT_HEADERS64 const *>(image_nt_headers())
                ->OptionalHeader;
}

PE::Sections PE::image_sections() const
{
    IMAGE_SECTION_HEADER const *begin = image_first_section();
    return Sections(begin, begin + image_file_header()->NumberOfSections);
}

PE::RuntimeFunctions PE::runtime_functions() const
{
    IMAGE_DATA_DIRECTORY const &directory_exception =
        image_optional_header64()
            ->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!directory_exception.Size) {
        return RuntimeFunctions(nullptr, nullptr);
    }
    RUNTIME_FUNCTION const *begin = reinterpret_cast<RUNTIME_FUNCTION const *>(
        virtual_to_raw_address(directory_exception.VirtualAddress));
    if (!begin) {
        return RuntimeFunctions(nullptr, nullptr);
    }
    RUNTIME_FUNCTION const *end =
        begin + directory_exception.Size / sizeof(RUNTIME_FUNCTION);
    return RuntimeFunctions(begin, end);
}

RUNTIME_FUNCTION const *PE::get_runtime_function(DWORD va) const
{
    if (auto it = runtime_function_map_.find(va);
        it != runtime_function_map_.end()) {
        return it->second;
    }
    return nullptr;
}

Byte const *PE::virtual_to_raw_address(DWORD va) const
{
    auto it =
        std::upper_bound(sections_by_va_.begin(),
                         sections_by_va_.end(),
                         va,
                         [](DWORD va, IMAGE_SECTION_HEADER const *section) {
                             return va < section->VirtualAddress;
                         });
    if (it == sections_by_va_.begin()) {
        return nullptr;
    }
    auto section = *std::prev(it);
    return data() + section->PointerToRawData + va - section->VirtualAddress;
}

DWORD PE::raw_to_virtual_address(Byte const *pointer) const
{
    auto raw_address = static_cast<DWORD>(pointer - data());
    auto section = get_section_by_raw_address(pointer);
    return raw_address - section->PointerToRawData + section->VirtualAddress;
}

Byte const *PE::get_entry_point() const
{
    return virtual_to_raw_address(
        image_optional_header64()->AddressOfEntryPoint);
}

Byte const *PE::get_begin(Byte const *pointer) const
{
    auto section = get_section_by_raw_address(pointer);
    return data() + section->PointerToRawData;
}

Byte const *PE::get_end(Byte const *pointer) const
{
    auto section = get_section_by_raw_address(pointer);
    return data() + section->PointerToRawData + section->SizeOfRawData;
}
