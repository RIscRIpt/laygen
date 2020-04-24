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
            Sections(IMAGE_SECTION_HEADER const *begin,
                     IMAGE_SECTION_HEADER const *end)
                : begin_(begin)
                , end_(end)
            {
            }

            inline IMAGE_SECTION_HEADER const *begin() const { return begin_; }
            inline IMAGE_SECTION_HEADER const *end() const { return end_; }

        private:
            IMAGE_SECTION_HEADER const *begin_;
            IMAGE_SECTION_HEADER const *end_;
        };

        PE(std::filesystem::path const &path);

        BYTE const *data() const;
        IMAGE_DOS_HEADER const *image_dos_header() const;
        IMAGE_FILE_HEADER const *image_file_header() const;
        IMAGE_OPTIONAL_HEADER64 const *image_optional_header64() const;
        Sections const image_sections() const;

        BYTE const *virtual_to_raw_address(DWORD va) const;
        DWORD raw_to_virtual_address(BYTE const *pointer) const;

        BYTE const *get_entry_point() const;

        BYTE const *get_begin(BYTE const *pointer) const;
        BYTE const *get_end(BYTE const *pointer) const;

    private:
        IMAGE_NT_HEADERS const *image_nt_headers() const;
        IMAGE_SECTION_HEADER const *image_first_section() const;
        IMAGE_SECTION_HEADER const *
        get_section_by_raw_address(BYTE const *pointer) const;

        Bytes bytes_;
        std::vector<IMAGE_SECTION_HEADER const *> sections_by_va_;
        std::vector<IMAGE_SECTION_HEADER const *> sections_by_raw_data_;
    };

}
