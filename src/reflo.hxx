#pragma once

#include "pe.hxx"
#include "cfgraph.hxx"

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

#ifndef NDEBUG
        void debug(std::ostream &os);
        void dump_instruction(std::ostream &os,
                              DWORD va,
                              ZydisDecodedInstruction const &instruction);
        void dump_cfgraph(std::ostream &os,
                          ZydisFormatter const &formatter,
                          CFGraph const &cfgraph);
#endif

    private:
        Instruction decode_instruction(Address address, Address end);

        void fill_cfgraph(CFGraph &cfgraph);
        void post_fill_cfgraph(CFGraph &cfgraph);
        void wait_before_analysis_run();
        void run_cfgraph_analysis(Address entry_point);
        void run_cfgraph_post_analysis(CFGraph &cfgraph);
        void find_and_analyze_cfgraphs();
        void promote_jumps_to_outer();
        void promote_jumps_to_inner();
        void post_analyze_cfgraphs();
        void wait_for_analysis();
        bool unknown_jumps_exist() const;

        Address pop_unprocessed_cfgraph();

        ZydisDecoder decoder_;
#ifndef NDEBUG
        ZydisFormatter formatter_;
#endif

        PE pe_;

        size_t max_analyzing_threads_;
        std::atomic<size_t> analyzing_threads_count_ = 0;
        std::mutex cfgraphs_mutex_;
        std::condition_variable cfgraphs_cv_;
        std::vector<std::thread> analyzing_threads_;
        std::unordered_set<Address> created_cfgraphs_;
        std::map<Address, std::unique_ptr<CFGraph>> cfgraphs_;
        std::deque<Address> unprocessed_cfgraphs_;
    };

}
