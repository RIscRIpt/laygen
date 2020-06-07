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
//#define DEBUG_FLO_SPLIT

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
    if (flo.end()) {
        end = *flo.end();
    }
    else {
        end = pe_.get_end(address);
    }
    while (address && address < end) {
        auto instruction = decode_instruction(address, end);
#ifdef DEBUG_ANALYSIS
        Dumper dumper;
        DWORD va = pe_.raw_to_virtual_address(address);
        dumper.dump_instruction(std::clog, va, *instruction);
#endif
        auto analysis_result = flo.analyze(address, std::move(instruction));
        if (analysis_result.status == Flo::Stop) {
            break;
        }
        address = analysis_result.next_address;
    }
    post_fill_flo(flo);
    // If we have end of the flo, trim unreachable instructions
    // after RET/JMP, e.g. NOP, INT3, etc.
    if (flo.end()) {
        trim_flo(flo);
    }
}

void Reflo::post_fill_flo(Flo &flo)
{
    while (auto address = flo.get_unanalized_inner_jump_dst()) {
        Address end;
        if (flo.end()) {
            end = *flo.end();
        }
        else {
            end = pe_.get_end(address);
        }
        while (address && address < end) {
            auto instruction = decode_instruction(address, end);
#ifdef DEBUG_POST_ANALYSIS
            Dumper dumper;
            DWORD va = pe_.raw_to_virtual_address(address);
            dumper.dump_instruction(std::clog, va, *instruction);
#endif
            auto analysis_result = flo.analyze(address, std::move(instruction));
            if (analysis_result.status == Flo::Stop) {
                break;
            }
            address = analysis_result.next_address;
        }
    }
}

void Reflo::trim_flo(Flo &flo)
{
    auto last = flo.get_disassembly().rbegin();
    auto it = last;
    while (is_inter_flo_filler(
        it->second->mnemonic) /* && !is_tail_mnemonic(it->second->mnemonic)*/) {
        ++it;
    }
    if (it != last) {
        flo.set_end(std::prev(it)->first);
    }
    else {
        flo.set_end(last->first + last->second->length);
    }
}

bool Reflo::can_split_flo(Flo &flo,
                          std::vector<Address> const &possible_splits) const
{
    for (auto possible_split : possible_splits) {
        if (possible_split >= flo.end()) {
            break;
        }
        bool can_split = true;
#ifdef DEBUG_FLO_SPLIT
        DWORD va_ep = pe_.raw_to_virtual_address(flo.entry_point);
        DWORD va_split = pe_.raw_to_virtual_address(possible_split);
        std::clog << std::hex << va_ep << ": possible split = " << va_split
                  << '\n';
#endif
        for (auto const &jumps : { flo.get_inner_jumps(),
                                   flo.get_unknown_jumps(),
                                   flo.get_outer_jumps() }) {
            for (auto const &[_, jump] : jumps) {
#ifdef DEBUG_FLO_SPLIT
                DWORD va_src = pe_.raw_to_virtual_address(jump.src);
                DWORD va_dst = pe_.raw_to_virtual_address(jump.dst);
                std::clog << "jump.src = " << std::hex << va_src
                          << ", va_dst = " << std::hex << va_dst
                          << ", va_split = " << std::hex << va_split << " : "
                          << (jump.src < possible_split
                              && jump.dst >= possible_split)
                          << '\n';
#endif
                if (jump.src < possible_split && jump.dst >= possible_split) {
                    can_split = false;
                    break;
                }
            }
            if (!can_split) {
                break;
            }
        }
#ifdef DEBUG_FLO_SPLIT
        std::clog << std::hex << va_ep << ": can_split " << can_split << " @ "
                  << va_split << '\n';
#endif
        if (can_split) {
            return true;
        }
    }
    return false;
}

std::vector<Address> Reflo::get_possible_flo_ends(Address entry_point) const
{
    DWORD va = pe_.raw_to_virtual_address(entry_point);
    std::vector<Address> possible_ends;
    auto runtime_function = pe_.get_runtime_function(va);
    while (runtime_function && runtime_function->BeginAddress == va
           && runtime_function->EndAddress) {
        if (auto raw_addr =
                pe_.virtual_to_raw_address(runtime_function->EndAddress);
            raw_addr) {
            possible_ends.push_back(raw_addr);
        }
        va = runtime_function->EndAddress;
        runtime_function = pe_.get_runtime_function(va);
    }
    return possible_ends;
}

void Reflo::wait_before_analysis_run()
{
    auto lock = std::unique_lock(flos_waiting_mutex_);
    flos_cv_.wait(lock, [this] {
        return analyzing_threads_count_ < max_analyzing_threads_;
    });
    ++analyzing_threads_count_;
}

void Reflo::run_flo_analysis(Address entry_point, Address reference)
{
    // Prevent recursive and duplicate analysis
    if (created_flos_.contains(entry_point)) {
        {
            // Wait for flo to be created
            auto lock = std::unique_lock(flos_waiting_mutex_);
            flos_cv_.wait(lock, [this, entry_point] {
                std::scoped_lock<std::mutex> flo_guard(flos_mutex_);
                return flos_.find(entry_point) != flos_.end();
            });
        }
        auto &flo = *flos_.at(entry_point);
        {
            std::scoped_lock<std::mutex> add_reference_guard(flo.mutex());
            flo.add_reference(reference);
        }
        return;
    }
    created_flos_.emplace(entry_point);
    wait_before_analysis_run();
    analyzing_threads_.emplace_back([this, entry_point, reference]() mutable {
        try {
            ScopeGuard decrement_analyzing_threads_count([this]() noexcept {
                auto lock = std::unique_lock(flos_waiting_mutex_);
                --analyzing_threads_count_;
                flos_cv_.notify_all();
            });

#ifdef DEBUG_ANALYSIS
            std::clog << "Analyzing: " << std::hex << std::setfill('0')
                      << std::setw(8) << pe_.raw_to_virtual_address(entry_point)
                      << '\n';
#endif
            auto possible_ends = get_possible_flo_ends(entry_point);
            std::optional<Address> end;
            if (!possible_ends.empty()) {
                end = possible_ends.back();
            }
            auto flo = std::make_unique<Flo>(pe_, entry_point, reference, end);
            fill_flo(*flo);
            if (possible_ends.size() > 1) {
                assert(!can_split_flo(*flo, possible_ends));
            }
            add_flo(std::move(flo));
        }
        catch (zyan_error const &e) {
            std::cerr << std::hex << std::setfill('0')
                      << "Failed to analyze flo " << std::setw(8)
                      << pe_.raw_to_virtual_address(entry_point) << ", error:\n"
                      << e.what() << '\n';
        }
    });
}

void Reflo::add_flo(std::unique_ptr<Flo> &&flo)
{
    auto entry_point = flo->entry_point;
    std::scoped_lock<std::mutex, std::mutex> adding_flo_guard(
        flos_mutex_,
        unprocessed_flos_mutex_);
    flos_.emplace(entry_point, std::move(flo));
    unprocessed_flos_.push_back(entry_point);
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
    std::scoped_lock<std::mutex> popping_flo_guard(unprocessed_flos_mutex_);
    auto address = unprocessed_flos_.front();
    unprocessed_flos_.pop_front();
    return address;
}

void Reflo::find_and_analyze_flos()
{
    run_flo_analysis(pe_.get_entry_point(), nullptr);
    while (true) {
        if (unprocessed_flos_.empty()) {
            // Wait for all analyzing threads
            auto lock = std::unique_lock(flos_waiting_mutex_);
            flos_cv_.wait(lock, [this] {
                return analyzing_threads_count_ == 0
                       || !unprocessed_flos_.empty();
            });
        }
        if (analyzing_threads_count_ == 0 && unprocessed_flos_.empty()) {
            break;
        }

        auto &flo = flos_[pop_unprocessed_flo()];

        // Iterate over ~~unique~~ all call destinations
        // All, because we collect references
        for (auto it = flo->get_calls().begin(), end = flo->get_calls().end();
             it != end;
             ++it) {
            auto const &call = it->second;
            run_flo_analysis(call.dst, call.src);
        }

        // Iterate over ~~unique~~ all outer jumps
        // All, because we collect references
        for (auto it = flo->get_outer_jumps().begin(),
                  end = flo->get_outer_jumps().end();
             it != end;
             ++it) {
            auto const &jump = it->second;
            run_flo_analysis(jump.dst, jump.src);
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

bool Reflo::is_tail_mnemonic(ZydisMnemonic mnemonic)
{
    switch (mnemonic) {
    case ZYDIS_MNEMONIC_RET:
    case ZYDIS_MNEMONIC_JMP:
        //
        return true;
    }
    return false;
}

bool Reflo::is_inter_flo_filler(ZydisMnemonic mnemonic)
{
    switch (mnemonic) {
    case ZYDIS_MNEMONIC_NOP:
    case ZYDIS_MNEMONIC_INT3:
        // TODO: find more inter flo fillers
        return true;
    }
    return false;
}

void Reflo::set_max_analyzing_threads(size_t amount)
{
    max_analyzing_threads_ = amount;
}

void Reflo::debug(std::ostream &os, DWORD va)
{
    Dumper dumper;
    run_flo_analysis(pe_.virtual_to_raw_address(va), nullptr);
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
