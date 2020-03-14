#include "pe.hxx"

#include <fstream>

using namespace rstc;

PE::PE(std::filesystem::path const &path)
    : bytes_(Bytes(path))
{
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

PIMAGE_FILE_HEADER PE::image_file_header()
{
    return &image_nt_headers()->FileHeader;
}

PIMAGE_OPTIONAL_HEADER32 PE::image_optional_header32()
{
    return &reinterpret_cast<PIMAGE_NT_HEADERS32>(image_nt_headers())->OptionalHeader;
}

PIMAGE_OPTIONAL_HEADER64 PE::image_optional_header64()
{
    return &reinterpret_cast<PIMAGE_NT_HEADERS64>(image_nt_headers())->OptionalHeader;
}

PE::Sections PE::image_sections()
{
    PIMAGE_SECTION_HEADER begin = image_first_section();
    return Sections(begin, begin + image_file_header()->NumberOfSections);
}

BYTE *PE::get_entry_point()
{
    DWORD entry_point = 0;
    auto file_header = image_file_header();
    switch (file_header->Machine) {
    case IMAGE_FILE_MACHINE_AMD64:
        entry_point = image_optional_header64()->AddressOfEntryPoint;
        break;
    default: throw std::runtime_error("unsupported architecture");
    }
    auto first_section = image_first_section();
    std::vector<PIMAGE_SECTION_HEADER> sections(file_header->NumberOfSections);
    for (size_t i = 0; i < sections.size(); i++) {
        sections[i] = &first_section[i];
    }
    std::sort(sections.begin(),
              sections.end(),
              [](PIMAGE_SECTION_HEADER a, PIMAGE_SECTION_HEADER b) {
                  return a->VirtualAddress < b->VirtualAddress;
              });
    auto pentry_section = std::upper_bound(sections.begin(),
                               sections.end(),
                               entry_point,
                               [](DWORD entry, PIMAGE_SECTION_HEADER section) {
                                   return entry < section->VirtualAddress;
                               });
    if (pentry_section == sections.begin()) {
        throw std::runtime_error("failed to find entry point");
    }
    auto entry_section = *(pentry_section - 1);
    return data() + entry_section->PointerToRawData + entry_point - entry_section->VirtualAddress;
}

BYTE *PE::get_section_data(IMAGE_SECTION_HEADER const &section)
{
    return data() + section.PointerToRawData;
}
