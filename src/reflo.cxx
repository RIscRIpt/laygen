#include "reflo.hxx"

#include "dumper.hxx"
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
//#define DEBUG_POST_ANALYSIS

using namespace rstc;

Reflo::Reflo(std::filesystem::path const &pe_path)
    : pe_(pe_path)
    , max_analyzing_threads_(std::thread::hardware_concurrency())
{
    ZYAN_THROW(ZydisDecoderInit(&decoder_,
                                ZYDIS_MACHINE_MODE_LONG_64,
                                ZYDIS_ADDRESS_WIDTH_64));
}

Flo *Reflo::get_entry_flo()
{
    return get_flo_by_address(pe_.get_entry_point());
}

Flo *Reflo::get_flo_by_address(Address address)
{
    if (flos_.empty()) {
        return nullptr;
    }
    if (auto it = flos_.upper_bound(address); it != flos_.begin()) {
        return std::prev(it)->second.get();
    }
    return nullptr;
}

std::pair<Address, Address> Reflo::get_analyzed_bounds() const
{
    if (flos_.empty()) {
        return { nullptr, nullptr };
    }
    auto last = flos_.rbegin()->second->get_disassembly().rbegin();
    return { flos_.begin()->first, last->first + last->second->length };
}

std::pair<DWORD, DWORD> Reflo::get_analyzed_va_bounds() const
{
    auto [first, last] = get_analyzed_bounds();
    if (first == nullptr || last == nullptr) {
        return { 0, 0 };
    }
    return { pe_.raw_to_virtual_address(first),
             pe_.raw_to_virtual_address(last) };
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

void Reflo::fill_flo(Flo &flo)
{
    Address address = flo.entry_point;
    Address end;
    if (flo.end) {
        end = *flo.end;
    }
    else {
        end = pe_.get_end(address);
    }
    while (address && address < end) {
        auto instruction = decode_instruction(address, end);
#ifdef DEBUG_ANALYSIS
        Dumper dumper;
        dumper.dump_instruction(std::clog,
                                pe_.raw_to_virtual_address(address),
                                *instruction);
#endif
        auto analysis_result = flo.analyze(address, std::move(instruction));
        if (!(analysis_result.status & Flo::Next) && !flo.end) {
            break;
        }
        address = analysis_result.next_address;
    }
    post_fill_flo(flo);
}

void Reflo::post_fill_flo(Flo &flo)
{
    while (auto address = flo.get_unanalized_inner_jump_dst()) {
        Address end;
        if (flo.end) {
            end = *flo.end;
        }
        else {
            end = pe_.get_end(address);
        }
        while (address && address < end) {
            auto instruction = decode_instruction(address, end);
#ifdef DEBUG_POST_ANALYSIS
            Dumper dumper;
            dumper.dump_instruction(std::clog,
                                    pe_.raw_to_virtual_address(address),
                                    *instruction);
#endif
            auto analysis_result = flo.analyze(address, std::move(instruction));
            if (!(analysis_result.status & Flo::Next) && !flo.end) {
                break;
            }
            address = analysis_result.next_address;
        }
    }
}

void Reflo::wait_before_analysis_run()
{
    auto lock = std::unique_lock(flos_mutex_);
    flos_cv_.wait(lock, [this] {
        return analyzing_threads_count_ < max_analyzing_threads_;
    });
    ++analyzing_threads_count_;
}

void Reflo::run_flo_analysis(Address entry_point)
{
    // Prevent recursive analysis
    if (created_flos_.contains(entry_point)) {
        return;
    }
    created_flos_.emplace(entry_point);
    wait_before_analysis_run();
    analyzing_threads_.emplace_back([this, entry_point]() mutable {
        try {
            ScopeGuard decrement_analyzing_threads_count([this]() noexcept {
                --analyzing_threads_count_;
                flos_cv_.notify_all();
            });

#ifdef DEBUG_ANALYSIS
            std::clog << "Analyzing: " << std::hex << std::setfill('0')
                      << std::setw(8) << pe_.raw_to_virtual_address(entry_point)
                      << '\n';
#endif

            std::optional<Address> end;
            auto runtime_function = pe_.get_runtime_function(
                pe_.raw_to_virtual_address(entry_point));
            if (runtime_function && runtime_function->EndAddress) {
                if (auto real_end = pe_.virtual_to_raw_address(
                        runtime_function->EndAddress);
                    real_end) {
                    end = real_end;
                }
            }
            auto flo = std::make_unique<Flo>(pe_, entry_point, end);
            fill_flo(*flo);

            {
                std::lock_guard<std::mutex> adding_flo_guard(flos_mutex_);
                flos_.emplace(entry_point, std::move(flo));
                unprocessed_flos_.push_back(entry_point);
            }
        }
        catch (zyan_error const &e) {
            std::cerr << std::hex << std::setfill('0')
                      << "Failed to analyze flo " << std::setw(8)
                      << pe_.raw_to_virtual_address(entry_point) << ", error:\n"
                      << e.what() << '\n';
        }
    });
}

void Reflo::run_flo_post_analysis(Flo &flo)
{
    wait_before_analysis_run();
    analyzing_threads_.emplace_back([&] {
        try {
            ScopeGuard decrement_analyzing_threads_count([this]() noexcept {
                --analyzing_threads_count_;
                flos_cv_.notify_all();
            });
            // Post fill/analysis cannot happen for functions with defined
            // boundaries, which can be found in RUNTIME_FUNCTION.
            assert(!pe_.get_runtime_function(
                pe_.raw_to_virtual_address(flo.entry_point)));
            post_fill_flo(flo);
        }
        catch (zyan_error const &e) {
            std::cerr << std::hex << std::setfill('0')
                      << "Failed to post analyze flo " << std::setw(8)
                      << pe_.raw_to_virtual_address(flo.entry_point)
                      << ", error:\n"
                      << e.what() << '\n';
        }
    });
}

Address Reflo::pop_unprocessed_flo()
{
    std::lock_guard<std::mutex> popping_flo_guard(flos_mutex_);
    auto address = unprocessed_flos_.front();
    unprocessed_flos_.pop_front();
    return address;
}

void Reflo::find_and_analyze_flos()
{
    run_flo_analysis(pe_.get_entry_point());
    while (true) {
        if (unprocessed_flos_.empty()) {
            // Wait for all analyzing threads
            auto lock = std::unique_lock(flos_mutex_);
            flos_cv_.wait(lock,
                          [this] { return analyzing_threads_count_ == 0; });
        }
        if (analyzing_threads_count_ == 0 && unprocessed_flos_.empty()) {
            break;
        }

        auto &flo = flos_[pop_unprocessed_flo()];

        // Iterate over unique call destinations
        for (auto it = flo->get_calls().begin(), end = flo->get_calls().end();
             it != end;
             it = flo->get_calls().upper_bound(it->first)) {
            auto const &call = it->second;
            run_flo_analysis(call.dst);
        }

        // Iterate over unique outer jumps
        for (auto it = flo->get_outer_jumps().begin(),
                  end = flo->get_outer_jumps().end();
             it != end;
             it = flo->get_outer_jumps().upper_bound(it->first)) {
            auto const &jump = it->second;
            run_flo_analysis(jump.dst);
        }
    }
    wait_for_analysis();
}

void Reflo::promote_jumps_to_outer()
{
    // Promote all unknown jumps to outer jumps
    // Because we have all flos, and we can assume that all
    // unknown jumps from a flos is "outer"
    // if dst is in list of existing flos_.
    for (auto const &[entry_point, flo] : flos_) {
        flo->promote_unknown_jumps(Jump::Outer, [this](Address dst) mutable {
            return flos_.contains(dst);
        });
    }
}

void Reflo::promote_jumps_to_inner()
{
    // Promote all unknown jumps to inner jumps,
    // as some unknown jumps were promoted to outer jumps,
    // the remaining jumps should be inner jumps.
    for (auto const &[entry_point, flo] : flos_) {
        bool needs_post_analysis = !flo->get_unknown_jumps().empty();
        flo->promote_unknown_jumps(Jump::Inner);
        if (needs_post_analysis) {
            unprocessed_flos_.push_back(entry_point);
        }
    }
}

void Reflo::post_analyze_flos()
{
    while (!unprocessed_flos_.empty()) {
        auto &flo = flos_[pop_unprocessed_flo()];
        run_flo_post_analysis(*flo);
    }
    wait_for_analysis();
}

void Reflo::analyze()
{
    find_and_analyze_flos();
    while (unknown_jumps_exist()) {
        promote_jumps_to_outer();
        // Tehnically, we can't promote unknown jumps to inner jumps, as
        // we still haven't explored the program as a whole, and some flos
        // (functions) might be unlisted yet.
        promote_jumps_to_inner();
        post_analyze_flos();
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
    return std::any_of(flos_.cbegin(), flos_.cend(), [](auto const &flo) {
        return !flo.second->get_unknown_jumps().empty();
    });
}

void Reflo::set_max_analyzing_threads(size_t amount)
{
    max_analyzing_threads_ = amount;
}

void Reflo::debug(std::ostream &os, DWORD va)
{
    Dumper dumper;
    run_flo_analysis(pe_.virtual_to_raw_address(va));
    wait_for_analysis();
    while (unknown_jumps_exist()) {
        promote_jumps_to_outer();
        // Tehnically, we can't promote unknown jumps to inner jumps, as
        // we still haven't explored the program as a whole, and some flos
        // (functions) might be unlisted yet.
        promote_jumps_to_inner();
        post_analyze_flos();
    }
    for (auto const &[addr, flo] : flos_) {
        dumper.dump_flo(os, *flo, pe_.raw_to_virtual_address(flo->entry_point));
    }
}
