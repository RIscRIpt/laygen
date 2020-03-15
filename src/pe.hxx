#pragma once

#include "bytes.hxx"

#include <filesystem>
#include <vector>

#include <Windows.h>

namespace rstc {

    class PE {
    public:
        class Sections {
        public:
            Sections(PIMAGE_SECTION_HEADER begin, PIMAGE_SECTION_HEADER end)
                : begin_(begin)
                , end_(end)
            {
            }

            inline PIMAGE_SECTION_HEADER begin() { return begin_; }
            inline PIMAGE_SECTION_HEADER end() { return end_; }

        private:
            PIMAGE_SECTION_HEADER begin_;
            PIMAGE_SECTION_HEADER end_;
        };

        PE(std::filesystem::path const &path);

        BYTE *data();
        PIMAGE_DOS_HEADER image_dos_header();
        PIMAGE_FILE_HEADER image_file_header();
        PIMAGE_OPTIONAL_HEADER32 image_optional_header32();
        PIMAGE_OPTIONAL_HEADER64 image_optional_header64();
        Sections image_sections();

        BYTE *virtual_to_raw_address(DWORD va);
        DWORD raw_to_virtual_address(BYTE *pointer);

        BYTE *get_entry_point();

        BYTE *get_end(BYTE *pointer);

    private:
        PIMAGE_NT_HEADERS image_nt_headers();
        PIMAGE_SECTION_HEADER image_first_section();
        PIMAGE_SECTION_HEADER get_section_by_raw_address(BYTE *pointer);

        Bytes bytes_;
        std::vector<PIMAGE_SECTION_HEADER> sections_by_va_;
        std::vector<PIMAGE_SECTION_HEADER> sections_by_raw_data_;
    };

}
