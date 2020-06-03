#pragma once

#include "reflo.hxx"

#include "Zydis/Zydis.h"

namespace rstc {

    class Restruc {
    public:
        Restruc(Reflo &reflo);

        void analyze();
        void set_max_analyzing_threads(size_t amount);

        void debug(std::ostream &os);

    private:
        using InstructionGroups = std::map<virt::Value, std::vector<Address>>;

        void run_analysis(Flo &flo);
        void wait_for_analysis();

        void analyze_flo(Flo &flo);

        Reflo &reflo_;
        PE const &pe_;

        size_t max_analyzing_threads_;
        std::atomic<size_t> analyzing_threads_count_ = 0;
        std::vector<std::thread> analyzing_threads_;
        std::mutex analyzing_threads_mutex_;
        std::condition_variable analyzing_threads_cv_;
    };

}
