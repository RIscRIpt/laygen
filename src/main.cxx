#include "reflo.hxx"

#include <iostream>

int wmain(int argc, wchar_t *argv[])
{
    if (argc != 2) {
        std::cerr << "restruct.exe <filename>\n";
        return EXIT_FAILURE;
    }

    try {
        rstc::Reflo reflo(argv[1]);
#ifdef NDEBUG
        reflo.set_max_analyzing_threads(128);
        reflo.analyze();
#else
        reflo.set_max_analyzing_threads(1);
        reflo.debug(std::cout);
#endif
    }
    catch (std::exception const &e) {
        std::cerr << e.what() << '\n';
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
