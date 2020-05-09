#include "reflo.hxx"
#include "restruc.hxx"

#include <iomanip>
#include <iostream>

int wmain(int argc, wchar_t *argv[])
{
    if (argc != 2) {
        std::cerr << "restruct.exe <filename>\n";
        return EXIT_FAILURE;
    }

    try {
        rstc::Reflo reflo(argv[1]);
        rstc::Restruc restruc(reflo);

        reflo.set_max_analyzing_threads(128);
        std::cout << "Reflo::analyze ...\n";
        reflo.analyze();
        auto analyzed = reflo.get_analyzed_va_bounds();
        std::cout << std::setfill('0') << "Analyzed: [" << std::hex
                  << std::setw(8) << analyzed.first << "; " << std::hex
                  << std::setw(8) << analyzed.second << "]\n";
        std::cout << "Restruc::analyze ...\n";
        restruc.analyze();
        restruc.debug(std::cout);
    }
    catch (std::exception const &e) {
        std::cerr << e.what() << '\n';
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
