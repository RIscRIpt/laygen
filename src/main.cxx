#include "reflo.hxx"
#include "restruc.hxx"

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
#ifdef NDEBUG
        reflo.set_max_analyzing_threads(128);
        reflo.analyze();
        restruc.analyze(reflo);
#else
        reflo.set_max_analyzing_threads(128);
        std::cout << "Reflo::analyze ...\n";
        reflo.analyze();
        std::cout << "Restruc::analyze ...\n";
        restruc.analyze();
        restruc.debug(std::cout);
#endif
    }
    catch (std::exception const &e) {
        std::cerr << e.what() << '\n';
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
