#include "restruc.hxx"

#include <iostream>

int wmain(int argc, wchar_t *argv[])
{
    if (argc != 2) {
        std::cerr << "restruct.exe <filename>\n";
        return EXIT_FAILURE;
    }

    try {
        rstc::Restruc restruc(argv[1]);
#ifdef NDEBUG
        restruc.analyze();
#else
        restruc.debug(std::cout);
#endif
    }
    catch (std::exception const &e) {
        std::cerr << e.what() << '\n';
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
