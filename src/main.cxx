#include "recontex.hxx"
#include "reflo.hxx"
#include "restruc.hxx"

#include <chrono>
#include <iomanip>
#include <iostream>

std::chrono::milliseconds measure(std::function<void(void)> fx)
{
    auto start = std::chrono::high_resolution_clock::now();
    fx();
    auto end = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
}

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
        rstc::Restruc restruc(reflo);

        // TODO: remove when developed
        restruc.set_max_analyzing_threads(1);

        std::chrono::milliseconds time;

        std::cout << "// Reflo::analyze ...\n";
        time = measure([&reflo] { reflo.analyze(); });
        auto analyzed = reflo.get_analyzed_va_bounds();
        std::cout << std::setfill('0') << "// Analyzed: [" << std::hex
                  << std::setw(8) << analyzed.first << "; " << std::hex
                  << std::setw(8) << analyzed.second << "], " << std::dec
                  << reflo.get_flos().size() << " functions in " << std::dec
                  << time.count() << "ms\n";
        std::cout << "// Recontex::analyze ...\n";
        time = measure([&recontex] { recontex.analyze(); });
        std::cout << "// Analyzed " << std::dec << reflo.get_flos().size()
                  << " functions in " << std::dec << time.count() << "ms\n";
        std::cout << "// Restruc::analyze ...\n";
        time = measure([&restruc] { restruc.analyze(); });
        std::cout << "// Analyzed " << std::dec << reflo.get_flos().size()
                  << " functions in " << std::dec << time.count() << "ms\n";
        restruc.dump(std::cout);
    }
#ifdef NDEBUG
    catch (std::exception const &e) {
        std::cerr << e.what() << '\n';
        return EXIT_FAILURE;
    }
#endif

    return EXIT_SUCCESS;
}
