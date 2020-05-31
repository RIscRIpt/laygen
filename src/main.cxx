#include "reflo.hxx"
#include "recontex.hxx"

#include <iomanip>
#include <iostream>

int wmain(int argc, wchar_t *argv[])
{
    if (argc != 2) {
        std::cerr << "recontext.exe <filename>\n";
        return EXIT_FAILURE;
    }

#ifdef NDEBUG
    try
#endif
    {
        rstc::Reflo reflo(argv[1]);
        rstc::Recontex recontex(reflo);

        std::cout << "Reflo::analyze ...\n";
        reflo.analyze();
        auto analyzed = reflo.get_analyzed_va_bounds();
        std::cout << std::setfill('0') << "Analyzed: [" << std::hex
                  << std::setw(8) << analyzed.first << "; " << std::hex
                  << std::setw(8) << analyzed.second << "]\n";
        recontex.set_max_analyzing_threads(1);
        std::cout << "Recontex::analyze ...\n";
        recontex.analyze();
        recontex.debug(std::cout);
    }
#ifdef NDEBUG
    catch (std::exception const &e) {
        std::cerr << e.what() << '\n';
        return EXIT_FAILURE;
    }
#endif

    return EXIT_SUCCESS;
}
