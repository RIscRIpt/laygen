#pragma once

#include "flo.hxx"
#include "pe.hxx"

#include <Zydis/Zydis.h>

#include <atomic>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <thread>
#include <unordered_set>

namespace rstc {

    class Reflo {
    public:
        Reflo(std::filesystem::path const &pe_path);

        void analyze();
        void set_max_analyzing_threads(size_t amount);

        void debug(std::ostream &os, DWORD va);

        Flo *get_entry_flo();
        Flo *get_flo_by_address(Address address);

        std::pair<Address, Address> get_analyzed_bounds() const;
        std::pair<DWORD, DWORD> get_analyzed_va_bounds() const;

        inline std::map<Address, std::unique_ptr<Flo>> &get_flos()
        {
            return flos_;
        }

        inline PE const &get_pe() const { return pe_; }

    private:
        Instruction decode_instruction(Address address, Address end);

        void fill_flo(Flo &flo);
        void post_fill_flo(Flo &flo);
        void wait_before_analysis_run();
        void run_flo_analysis(Address entry_point);
        void run_flo_post_analysis(Flo &flo);
        void find_and_analyze_flos();
        void promote_jumps_to_outer();
        void promote_jumps_to_inner();
        void post_analyze_flos();
        void wait_for_analysis();
        bool unknown_jumps_exist() const;

        Address pop_unprocessed_flo();

        ZydisDecoder decoder_;

        PE pe_;

        size_t max_analyzing_threads_;
        std::atomic<size_t> analyzing_threads_count_ = 0;
        std::mutex flos_mutex_;
        std::condition_variable flos_cv_;
        std::vector<std::thread> analyzing_threads_;
        std::unordered_set<Address> created_flos_;
        std::map<Address, std::unique_ptr<Flo>> flos_;
        std::deque<Address> unprocessed_flos_;
    };

}
