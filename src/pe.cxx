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
    sections_by_va_ =
        std::vector<PIMAGE_SECTION_HEADER>(file_header->NumberOfSections);
    sections_by_raw_data_ =
        std::vector<PIMAGE_SECTION_HEADER>(file_header->NumberOfSections);
    for (size_t i = 0; i < file_header->NumberOfSections; i++) {
        sections_by_va_[i] = &first_section[i];
        sections_by_raw_data_[i] = &first_section[i];
    }
    std::sort(sections_by_va_.begin(),
              sections_by_va_.end(),
              [](PIMAGE_SECTION_HEADER a, PIMAGE_SECTION_HEADER b) {
                  return a->VirtualAddress < b->VirtualAddress;
              });
    std::sort(sections_by_raw_data_.begin(),
              sections_by_raw_data_.end(),
              [](PIMAGE_SECTION_HEADER a, PIMAGE_SECTION_HEADER b) {
                  return a->PointerToRawData < b->PointerToRawData;
              });
}

BYTE *PE::data()
{
    return bytes_.data();
}

PIMAGE_DOS_HEADER PE::image_dos_header()
{
    return reinterpret_cast<PIMAGE_DOS_HEADER>(data());
}

PIMAGE_NT_HEADERS PE::image_nt_headers()
{
    return reinterpret_cast<PIMAGE_NT_HEADERS>(data()
                                               + image_dos_header()->e_lfanew);
}

PIMAGE_SECTION_HEADER PE::image_first_section()
{
    return IMAGE_FIRST_SECTION(image_nt_headers());
}

PIMAGE_SECTION_HEADER PE::get_section_by_raw_address(BYTE *pointer)
{
    auto psection =
        std::upper_bound(sections_by_raw_data_.begin(),
                         sections_by_raw_data_.end(),
                         static_cast<DWORD>(pointer - data()),
                         [](DWORD raw_address, PIMAGE_SECTION_HEADER section) {
                             return raw_address < section->PointerToRawData;
                         });
    if (psection == sections_by_raw_data_.begin()) {
        throw std::runtime_error("invalid raw address");
    }
    return *(psection - 1);
}

PIMAGE_FILE_HEADER PE::image_file_header()
{
    return &image_nt_headers()->FileHeader;
}

PIMAGE_OPTIONAL_HEADER32 PE::image_optional_header32()
{
    return &reinterpret_cast<PIMAGE_NT_HEADERS32>(image_nt_headers())
                ->OptionalHeader;
}

PIMAGE_OPTIONAL_HEADER64 PE::image_optional_header64()
{
    return &reinterpret_cast<PIMAGE_NT_HEADERS64>(image_nt_headers())
                ->OptionalHeader;
}

PE::Sections PE::image_sections()
{
    PIMAGE_SECTION_HEADER begin = image_first_section();
    return Sections(begin, begin + image_file_header()->NumberOfSections);
}

BYTE *PE::virtual_to_raw_address(DWORD va)
{
    auto psection =
        std::upper_bound(sections_by_va_.begin(),
                         sections_by_va_.end(),
                         va,
                         [](DWORD va, PIMAGE_SECTION_HEADER section) {
                             return va < section->VirtualAddress;
                         });
    if (psection == sections_by_va_.begin()) {
        throw std::runtime_error("failed to find entry point");
    }
    auto section = *(psection - 1);
    return data() + section->PointerToRawData + va - section->VirtualAddress;
}

DWORD PE::raw_to_virtual_address(BYTE *pointer)
{
    auto raw_address = static_cast<DWORD>(pointer - data());
    auto section = get_section_by_raw_address(pointer);
    return raw_address - section->PointerToRawData + section->VirtualAddress;
}

BYTE *PE::get_entry_point()
{
    return virtual_to_raw_address(
        image_optional_header64()->AddressOfEntryPoint);
}

BYTE *PE::get_begin(BYTE *pointer)
{
    auto section = get_section_by_raw_address(pointer);
    return data() + section->PointerToRawData;
}

BYTE *PE::get_end(BYTE *pointer)
{
    auto section = get_section_by_raw_address(pointer);
    return data() + section->PointerToRawData + section->SizeOfRawData;
}
