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

PIMAGE_FILE_HEADER PE::image_file_header()
{
    return &image_nt_headers()->FileHeader;
}

PIMAGE_OPTIONAL_HEADER32 PE::image_optional_header32()
{
    return &reinterpret_cast<PIMAGE_NT_HEADERS32>(data())->OptionalHeader;
}

PIMAGE_OPTIONAL_HEADER64 PE::image_optional_header64()
{
    return &reinterpret_cast<PIMAGE_NT_HEADERS64>(data())->OptionalHeader;
}

PE::Sections PE::image_sections()
{
    PIMAGE_SECTION_HEADER begin = IMAGE_FIRST_SECTION(image_nt_headers());
    return Sections(begin, begin + image_file_header()->NumberOfSections);
}

BYTE *PE::get_entry_point()
{
    // FIXME: This is invalid
    switch (image_file_header()->Machine) {
    case IMAGE_FILE_MACHINE_I386:
        return data() + image_optional_header32()->AddressOfEntryPoint;
    case IMAGE_FILE_MACHINE_AMD64:
        return data() + image_optional_header64()->AddressOfEntryPoint;
    }
    return nullptr;
}

BYTE *PE::get_section_data(IMAGE_SECTION_HEADER const &section)
{
    return data() + section.PointerToRawData;
}
