#include "reflo.hxx"
#include "scope_guard.hxx"
#include "zyan_error.hxx"

#include <cinttypes>
#include <cstdio>
#include <execution>
#include <functional>
#include <iomanip>
#include <iostream>
#include <string>

//#define DEBUG_ANALYSIS

using namespace rstc;

#define ZYAN_THROW(expr)               \
    do {                               \
        ZyanStatus _status = (expr);   \
        if (ZYAN_FAILED(_status)) {    \
            throw zyan_error(_status); \
        }                              \
    } while (0)

Reflo::Reflo(std::filesystem::path const &pe_path)
    : pe_(pe_path)
    , max_analyzing_threads_(std::thread::hardware_concurrency())
{
    ZYAN_THROW(ZydisDecoderInit(&decoder_,
                                ZYDIS_MACHINE_MODE_LONG_64,
                                ZYDIS_ADDRESS_WIDTH_64));
#ifndef NDEBUG
    ZYAN_THROW(ZydisFormatterInit(&formatter_, ZYDIS_FORMATTER_STYLE_INTEL));
#endif
}

Instruction Reflo::decode_instruction(Address address, Address end)
{
    Instruction instruction = std::make_unique<ZydisDecodedInstruction>();
    ZYAN_THROW(ZydisDecoderDecodeBuffer(&decoder_,
                                        address,
                                        end - address,
                                        instruction.get()));
    return std::move(instruction);
}

void Reflo::fill_cfgraph(CFGraph &cfgraph)
{
    Address address;
    Address next_address;
    if (cfgraph.get_disassembly().empty()) {
        next_address = cfgraph.entry_point;
    }
    else {
        next_address = cfgraph.get_disassembly().rbegin()->first;
    }
    Address end = pe_.get_end(next_address);
    while (true) {
        address = next_address;
        if (address == nullptr || address >= end) {
            break;
        }
        auto instruction = decode_instruction(address, end);
#ifdef DEBUG_ANALYSIS
        dump_instruction(std::clog,
                         pe_.raw_to_virtual_address(address),
                         instruction);
#endif
        auto analysis_status =
            cfgraph.analyze(pe_, address, std::move(instruction));
        next_address = analysis_status.next_address;
    }
}

void Reflo::post_fill_cfgraph(CFGraph &cfgraph)
{
    while (auto address = cfgraph.get_unanalized_inner_jump_dst()) {
        auto next_address = address;
        auto end = pe_.get_end(address);
        while (true) {
            address = next_address;
            if (address == nullptr || address >= end) {
                break;
            }
            auto instruction = decode_instruction(address, end);
#ifdef DEBUG_ANALYSIS
            dump_instruction(std::clog,
                             pe_.raw_to_virtual_address(address),
                             instruction);
#endif
            auto analysis_status =
                cfgraph.analyze(pe_, address, std::move(instruction));
            next_address = analysis_status.next_address;
        }
    }
}

void Reflo::wait_before_analysis_run()
{
    cfgraphs_cv_.wait(std::unique_lock(cfgraphs_mutex_), [this] {
        return analyzing_threads_count_ < max_analyzing_threads_;
    });
    ++analyzing_threads_count_;
}

void Reflo::run_cfgraph_analysis(Address entry_point)
{
    // Prevent recursive analysis
    if (created_cfgraphs_.contains(entry_point)) {
        return;
    }
    created_cfgraphs_.emplace(entry_point);
    wait_before_analysis_run();
    analyzing_threads_.emplace_back([this, entry_point]() mutable {
        try {
            ScopeGuard decrement_analyzing_threads_count([this]() noexcept {
                --analyzing_threads_count_;
                cfgraphs_cv_.notify_all();
            });

#ifdef DEBUG_ANALYSIS
            std::clog << "Analyzing: " << std::hex << std::setfill('0')
                      << std::setw(8) << pe_.raw_to_virtual_address(entry_point)
                      << '\n';
#endif

            auto cfgraph = std::make_unique<CFGraph>(entry_point);
            fill_cfgraph(*cfgraph);

            {
                std::lock_guard<std::mutex> adding_cfgraph_guard(
                    cfgraphs_mutex_);
                cfgraphs_.emplace(entry_point, std::move(cfgraph));
                unprocessed_cfgraphs_.push_back(entry_point);
            }
        }
        catch (zyan_error const &e) {
            std::cerr << std::hex << std::setfill('0')
                      << "Failed to analyze cfgraph " << std::setw(8)
                      << pe_.raw_to_virtual_address(entry_point) << ", error:\n"
                      << e.what() << '\n';
        }
    });
}

void Reflo::run_cfgraph_post_analysis(CFGraph &cfgraph)
{
    wait_before_analysis_run();
    analyzing_threads_.emplace_back([&] {
        try {
            ScopeGuard decrement_analyzing_threads_count([this]() noexcept {
                --analyzing_threads_count_;
                cfgraphs_cv_.notify_all();
            });
            post_fill_cfgraph(cfgraph);
        }
        catch (zyan_error const &e) {
            std::cerr << std::hex << std::setfill('0')
                      << "Failed to post analyze cfgraph " << std::setw(8)
                      << pe_.raw_to_virtual_address(cfgraph.entry_point)
                      << ", error:\n"
                      << e.what() << '\n';
        }
    });
}

Address Reflo::pop_unprocessed_cfgraph()
{
    std::lock_guard<std::mutex> popping_cfgraph_guard(cfgraphs_mutex_);
    auto address = unprocessed_cfgraphs_.front();
    unprocessed_cfgraphs_.pop_front();
    return address;
}

void Reflo::find_and_analyze_cfgraphs()
{
    run_cfgraph_analysis(pe_.get_entry_point());
    while (true) {
        if (unprocessed_cfgraphs_.empty()) {
            // Wait for all analyzing threads
            cfgraphs_cv_.wait(std::unique_lock(cfgraphs_mutex_),
                              [this] { return analyzing_threads_count_ == 0; });
        }
        if (analyzing_threads_count_ == 0 && unprocessed_cfgraphs_.empty()) {
            break;
        }

        auto &cfgraph = cfgraphs_[pop_unprocessed_cfgraph()];

        // Iterate over unique call destinations
        for (auto it = cfgraph->get_calls().begin(),
                  end = cfgraph->get_calls().end();
             it != end;
             it = cfgraph->get_calls().upper_bound(it->first)) {
            auto const &jump = it->second;
            run_cfgraph_analysis(jump.dst);
        }

        // Iterate over unique outer jumps
        for (auto it = cfgraph->get_outer_jumps().begin(),
                  end = cfgraph->get_outer_jumps().end();
             it != end;
             it = cfgraph->get_outer_jumps().upper_bound(it->first)) {
            auto const &jump = it->second;
            run_cfgraph_analysis(jump.dst);
        }
    }
    wait_for_analysis();
}

void Reflo::promote_jumps_to_outer()
{
    // Promote all unknown jumps to outer jumps
    // Because we have all cfgraphs, and we can assume that all
    // unknown jumps from a cfgraphs is "outer"
    // if dst is in list of existing cfgraphs_.
    for (auto const &[entry_point, cfgraph] : cfgraphs_) {
        cfgraph->promote_unknown_jumps(
            Jump::Outer,
            [this](Address dst) mutable { return cfgraphs_.contains(dst); });
    }
}

void Reflo::promote_jumps_to_inner()
{
    // Promote all unknown jumps to inner jumps,
    // as some unknown jumps were promoted to outer jumps,
    // the remaining jumps should be inner jumps.
    for (auto const &[entry_point, cfgraph] : cfgraphs_) {
        bool needs_post_analysis = !cfgraph->get_unknown_jumps().empty();
        cfgraph->promote_unknown_jumps(Jump::Inner);
        if (needs_post_analysis) {
            unprocessed_cfgraphs_.push_back(entry_point);
        }
    }
}

void Reflo::post_analyze_cfgraphs()
{
    while (!unprocessed_cfgraphs_.empty()) {
        auto &cfgraph = cfgraphs_[pop_unprocessed_cfgraph()];
        run_cfgraph_post_analysis(*cfgraph);
    }
    wait_for_analysis();
}

void Reflo::analyze()
{
    find_and_analyze_cfgraphs();
    while (unknown_jumps_exist()) {
        promote_jumps_to_outer();
        // Tehnically, we can't promote unknown jumps to inner jumps, as
        // we still haven't explored the program as a whole, and some cfgraphs
        // (functions) might be unlisted yet.
        promote_jumps_to_inner();
        post_analyze_cfgraphs();
    }
}

void Reflo::wait_for_analysis()
{
    std::for_each(analyzing_threads_.begin(),
                  analyzing_threads_.end(),
                  [](std::thread &t) { t.join(); });
    analyzing_threads_.clear();
}

bool Reflo::unknown_jumps_exist() const
{
    return std::any_of(cfgraphs_.cbegin(),
                       cfgraphs_.cend(),
                       [this](auto const &cfgraph) {
                           return !cfgraph.second->get_unknown_jumps().empty();
                       });
}

void Reflo::set_max_analyzing_threads(size_t amount)
{
    max_analyzing_threads_ = amount;
}

#ifndef NDEBUG

void Reflo::debug(std::ostream &os)
{
    analyze();
    for (auto const &f : cfgraphs_) {
        dump_cfgraph(os, formatter_, *f.second);
    }
}

void Reflo::dump_instruction(std::ostream &os,
                             DWORD va,
                             ZydisDecodedInstruction const &instruction)
{
    char buffer[256];
    ZYAN_THROW(ZydisFormatterFormatInstruction(&formatter_,
                                               &instruction,
                                               buffer,
                                               sizeof(buffer),
                                               va));
    os << std::hex << std::setfill('0') << std::setw(8) << va << "    "
       << buffer << '\n';
}

void Reflo::dump_cfgraph(std::ostream &os,
                         ZydisFormatter const &formatter,
                         CFGraph const &cfgraph)
{
    char buffer[256];
    os << std::hex << std::setfill('0');
    os << std::setw(8) << pe_.raw_to_virtual_address(cfgraph.entry_point)
       << ":\n";
    for (auto const &[address, instruction] : cfgraph.get_disassembly()) {
        auto va = pe_.raw_to_virtual_address(address);
        dump_instruction(os, va, *instruction);
    }
    os << '\n';
}

#endif
