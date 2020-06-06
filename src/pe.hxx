#pragma once

#include "bytes.hxx"

#include <filesystem>
#include <unordered_map>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

namespace rstc {

    class PE {
    public:
        template<typename T>
        class Range {
        public:
            Range(T const *begin, T const *end)
                : begin_(begin)
                , end_(end)
            {
            }

            inline T const *begin() const { return begin_; }
            inline T const *end() const { return end_; }

        private:
            T const *begin_;
            T const *end_;
        };

        using Sections = Range<IMAGE_SECTION_HEADER>;
        using RuntimeFunctions = Range<RUNTIME_FUNCTION>;

        PE(std::filesystem::path const &path);

        Byte const *data() const;
        IMAGE_DOS_HEADER const *image_dos_header() const;
        IMAGE_FILE_HEADER const *image_file_header() const;
        IMAGE_OPTIONAL_HEADER64 const *image_optional_header64() const;
        Sections image_sections() const;
        RuntimeFunctions runtime_functions() const;
        RUNTIME_FUNCTION const *get_runtime_function(DWORD va) const;

        Byte const *virtual_to_raw_address(DWORD va) const;
        DWORD raw_to_virtual_address(Byte const *pointer) const;

        Byte const *get_entry_point() const;

        Byte const *get_begin(Byte const *pointer) const;
        Byte const *get_end(Byte const *pointer) const;

    private:
        IMAGE_NT_HEADERS const *image_nt_headers() const;
        IMAGE_SECTION_HEADER const *image_first_section() const;
        IMAGE_SECTION_HEADER const *
        get_section_by_raw_address(Byte const *pointer) const;

        Bytes bytes_;
        std::vector<IMAGE_SECTION_HEADER const *> sections_by_va_;
        std::vector<IMAGE_SECTION_HEADER const *> sections_by_raw_data_;

        std::unordered_map<DWORD, RUNTIME_FUNCTION const *>
            runtime_function_map_;
    };

}
