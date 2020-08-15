#include "restruc.hxx"

#include "dumper.hxx"
#include "scope_guard.hxx"
#include "struc.hxx"
#include "utils/adapters.hxx"
#include "utils/hash.hxx"

#include <iomanip>
#include <iostream>
#include <sstream>

using namespace rstc;

#define DEBUG_ANALYSIS
#define DEBUG_INTRA_LINK
#define DEBUG_INTER_LINK
#define DEBUG_MERGE

Restruc::Restruc(Reflo const &reflo, Recontex const &recontex)
    : reflo_(reflo)
    , recontex_(recontex)
    , pe_(reflo.get_pe())
    , max_analyzing_threads_(std::thread::hardware_concurrency())
{
}

void Restruc::analyze()
{
    for (auto const &[address, flo] : reflo_.get_flos()) {
        run_analysis(*flo, &Restruc::analyze_flo);
    }
#ifdef DEBUG_ANALYSIS_PROGRESS
    std::clog << "Waiting for analysis to finish ...\n";
#endif
    wait_for_analysis();
#ifdef DEBUG_ANALYSIS_PROGRESS
    std::clog << "Done.\n";
#endif
    for (auto const &[address, flo] : reflo_.get_flos()) {
        // No reference, no link
        if (flo->get_references().empty()) {
            continue;
        }
        // No strucs, no link
        if (domains_.find(flo->entry_point) == domains_.end()) {
            continue;
        }
        run_analysis(*flo, &Restruc::inter_link_flo_strucs);
    }
#ifdef DEBUG_ANALYSIS_PROGRESS
    std::clog << "Waiting for analysis to finish ...\n";
#endif
    wait_for_analysis();
#ifdef DEBUG_ANALYSIS_PROGRESS
    std::clog << "Done.\n";
#endif
}

void Restruc::set_max_analyzing_threads(size_t amount)
{
    max_analyzing_threads_ = amount;
}

Restruc::FloDomain *Restruc::get_flo_domain(Flo const &flo)
{
    if (auto it = domains_.find(flo.entry_point); it != domains_.end()) {
        return &it->second;
    }
    return nullptr;
}

void Restruc::run_analysis(Flo &flo, void (Restruc::*callback)(Flo &))
{
    auto lock = std::unique_lock(analyzing_threads_mutex_);
    analyzing_threads_cv_.wait(lock, [this] {
        return analyzing_threads_count_ < max_analyzing_threads_;
    });
    ++analyzing_threads_count_;
    analyzing_threads_.emplace_back([this, &flo, callback]() mutable {
        ScopeGuard decrement_analyzing_threads_count([this]() noexcept {
            std::scoped_lock<std::mutex> notify_guard(analyzing_threads_mutex_);
            --analyzing_threads_count_;
            analyzing_threads_cv_.notify_all();
        });
#ifdef DEBUG_ANALYSIS_PROGRESS
        std::clog << "Running analysis on: " << std::dec
                  << analyzing_threads_.size() << '/' << std::dec
                  << reflo_.get_flos().size() << ": " << std::setfill('0')
                  << std::setw(8) << std::hex
                  << pe_.raw_to_virtual_address(flo.entry_point) << '\n';
#endif
        (this->*callback)(flo);
    });
}

void Restruc::wait_for_analysis()
{
    std::for_each(analyzing_threads_.begin(),
                  analyzing_threads_.end(),
                  [](std::thread &t) { t.join(); });
    analyzing_threads_.clear();
}

void Restruc::analyze_flo(Flo &flo)
{
#ifdef DEBUG_ANALYSIS
    Dumper dumper;
    DWORD va = pe_.raw_to_virtual_address(flo.entry_point);
    std::clog << std::setfill('0') << std::hex << std::setw(8)
              << "Analyzing Flo @ "
              << pe_.raw_to_virtual_address(flo.entry_point) << " ...\n";
#endif
    FloDomain flo_domain;
    ValueGroups groups;
    auto const &disassembly = flo.get_disassembly();
    auto const &flo_contexts = recontex_.get_contexts(flo);
    for (auto const &[address, instruction] : disassembly) {
#ifdef DEBUG_ANALYSIS
        DWORD va = pe_.raw_to_virtual_address(address);
#endif
        for (ZyanU8 i = 0; i < instruction->operand_count; i++) {
            auto const &op = instruction->operands[i];
            if (op.visibility != ZYDIS_OPERAND_VISIBILITY_EXPLICIT) {
                continue;
            }
            if (op.type == ZYDIS_OPERAND_TYPE_REGISTER
                && op.actions & ZYDIS_OPERAND_ACTION_MASK_READ
                && !(op.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE)) {
                for (auto const &context : utils::multimap_values(
                         flo_contexts.equal_range(address))) {
                    if (auto reg = context.get_register(op.reg.value); reg) {
#ifdef DEBUG_ANALYSIS
                        std::clog << "root_map: \t";
                        dumper.dump_value(std::clog, *reg);
                        std::clog << " -> "
                                  << ZydisRegisterGetString(op.reg.value);
                        std::clog << "\t: ";
                        dumper.dump_instruction(std::clog, va, *instruction);
#endif
                        flo_domain.root_map.emplace(*reg, op.reg.value);
                    }
                }
            }
            else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY
                     && op.mem.base != ZYDIS_REGISTER_NONE
                     // TODO: analyze stack
                     && op.mem.base != ZYDIS_REGISTER_RSP
                     && op.mem.base != ZYDIS_REGISTER_RIP) {
#ifdef DEBUG_ANALYSIS
                std::clog << "base_map: \t" << std::hex << va << " -> "
                          << ZydisRegisterGetString(op.mem.base) << "\t: ";
                dumper.dump_instruction(std::clog, va, *instruction);
#endif
                flo_domain.base_map.emplace(address, op.mem.base);
                for (auto const &context : utils::multimap_values(
                         flo_contexts.equal_range(address))) {
                    if (auto reg = context.get_register(op.mem.base); reg) {
                        if (!reg->is_symbolic()
                            && Recontex::points_to_stack(reg->value())) {
                            continue;
                        }
#ifdef DEBUG_ANALYSIS
                        std::clog << "group ";
                        dumper.dump_value(std::clog, *reg);
                        std::clog
                            << " \tbase_regs: "
                            << (reg->source() ?
                                    pe_.raw_to_virtual_address(reg->source()) :
                                    0)
                            << " -> "
                            << ZydisRegisterGetString(op.mem.base);
                        std::clog << " \trel_instr: ";
                        dumper.dump_instruction(std::clog, va, *instruction);
#endif
                        auto &group = groups[*reg];
                        group.relevant_instructions.emplace(address,
                                                            instruction.get());
                        group.base_regs.emplace(reg->source(), op.mem.base);
                    }
                }
            }
        }
    }
    if (!groups.empty()) {
        create_flo_strucs(flo, flo_domain, std::move(groups));
        intra_link_flo_strucs(flo, flo_contexts, flo_domain);
    }
    if (!flo_domain.empty()) {
        add_flo_domain(flo, std::move(flo_domain));
    }
}

void Restruc::create_flo_strucs(Flo &flo,
                                FloDomain &flo_domain,
                                ValueGroups &&groups)
{
#ifdef DEBUG_ANALYSIS
    Dumper dumper;
    DWORD va = pe_.raw_to_virtual_address(flo.entry_point);
    if (groups.empty()) {
        return;
    }
    std::clog << std::setfill('0') << std::hex << std::right
              << pe_.raw_to_virtual_address(flo.entry_point) << ":\n";
#endif
    for (auto &&[value, sd] : groups) {
#ifdef DEBUG_ANALYSIS
        dumper.dump_value(std::clog, value);
        std::clog << ":\n";
#endif
        sd.struc = std::make_shared<Struc>(generate_struc_name(flo, value));
        for (auto const [address, instruction] : sd.relevant_instructions) {
#ifdef DEBUG_ANALYSIS
            dumper.dump_instruction(std::clog,
                                    pe_.raw_to_virtual_address(address),
                                    *instruction);
#endif
            add_struc_field(flo, address, *sd.struc, *instruction);
        }
#ifdef DEBUG_ANALYSIS
        std::clog << '\n';
        sd.struc->print(std::clog);
        std::clog << '\n';
#endif
        sd.base_flo = &flo;
        flo_domain.strucs.emplace(value, std::move(sd));
    }
#ifdef DEBUG_ANALYSIS
    std::clog << '\n';
#endif
}

void Restruc::intra_link_flo_strucs(Flo &flo,
                                    Recontex::FloContexts const &flo_contexts,
                                    FloDomain &flo_domain)
{
    auto &strucs = flo_domain.strucs;
    if (strucs.size() < 2) {
        return;
    }
#ifdef DEBUG_INTRA_LINK
    Dumper dumper;
    std::clog << "Linking strucs...\n";
#endif
    for (auto &[value, sd] : flo_domain.strucs) {
        if (!value.source()) {
            continue;
        }
        auto const &instruction = *flo.get_instruction(value.source());
        if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV) {
            auto const &src = instruction.operands[1];
            if (src.type != ZYDIS_OPERAND_TYPE_MEMORY) {
                continue;
            }
            for (auto const &context : utils::multimap_values(
                     flo_contexts.equal_range(value.source()))) {
                if (auto reg = context.get_register(src.mem.base); reg) {
                    if (auto it = strucs.find(*reg); it != strucs.end()) {
                        auto &parent_struc = *it->second.struc;
                        size_t offset = 0;
                        if (src.mem.disp.has_displacement) {
                            if (src.mem.disp.value < 0) {
                                continue;
                            }
                            offset = src.mem.disp.value;
                        }
#ifdef DEBUG_INTRA_LINK
                        std::clog << "Linking " << sd.struc->name() << " with "
                                  << parent_struc.name() << " by "
                                  << ZydisRegisterGetString(src.mem.base) << ' ';
                        dumper.dump_value(std::clog, *reg);
                        std::clog << " : ";
                        dumper.dump_instruction(
                            std::clog,
                            pe_.raw_to_virtual_address(value.source()),
                            instruction);
#endif
                        parent_struc.add_pointer_field(offset,
                                                       1,
                                                       sd.struc.get());
                    }
                }
            }
        }
    }
}

void Restruc::add_flo_domain(Flo &flo, FloDomain &&flo_domain)
{
    std::scoped_lock<std::mutex, std::mutex> add_strucs_guard(
        modify_access_domains_mutex_,
        modify_access_strucs_mutex_);
    for (auto &[_, domain] : flo_domain.strucs) {
        strucs_.emplace(domain.struc->name(), domain.struc);
    }
    auto [it, inserted] =
        domains_.emplace(flo.entry_point, std::move(flo_domain));
    assert(inserted);
}

void Restruc::inter_link_flo_strucs(Flo &flo)
{
    auto &flo_domain = domains_.at(flo.entry_point);
    if (flo_domain.strucs.empty()) {
        return;
    }
#ifdef DEBUG_INTER_LINK
    DWORD va = pe_.raw_to_virtual_address(flo.entry_point);
    std::clog << "Inter linking strucs of flo @ " << std::setfill('0')
              << std::hex << std::setw(8) << va << '\n';
#endif
    auto const &flo_contexts = recontex_.get_contexts(flo);
    for (auto &[value, sd] : flo_domain.strucs) {
        // If StrucDomain hasn't "root" address, then
        // this StrucDomain is based on register which
        // came from outside of this Flo.
        // Otherwise, it's a memory/stack-based StrucDomain.
        std::unordered_set<Address> visited;
        if (value.source()) {
            auto const &instruction = *flo.get_instruction(value.source());
            auto const &src = instruction.operands[1];
            if (instruction.mnemonic != ZYDIS_MNEMONIC_MOV
                || src.type != ZYDIS_OPERAND_TYPE_MEMORY
                || !Recontex::points_to_stack(src.mem.base,
                                              value.source(),
                                              flo_contexts)) {
                continue;
            }
            std::unordered_set<int> linked_arg;
            for (auto const &context : utils::multimap_values(
                     flo_contexts.equal_range(value.source()))) {
                if (auto address = Recontex::get_memory_address(src, context);
                    !address.is_symbolic()) {
                    auto argument =
                        Recontex::stack_argument_number(address.value());
                    inter_link_flo_strucs_via_stack(flo, sd, argument, visited);
                }
            }
        }
        else {
            auto base_regs = sd.base_regs.equal_range(nullptr);
            for (auto it = base_regs.first; it != base_regs.second; ++it) {
                inter_link_flo_strucs_via_register(flo,
                                                   sd,
                                                   it->second,
                                                   visited);
            }
        }
    }
}

void Restruc::inter_link_flo_strucs_via_stack(
    Flo const &flo,
    StrucDomain const &sd,
    unsigned argument,
    std::unordered_set<Address> &visited)
{
#ifdef DEBUG_INTER_LINK
    Dumper dumper;
#endif
    for (auto ref : flo.get_references()) {
        if (visited.contains(ref)) {
            continue;
        }
        visited.insert(ref);
#ifdef DEBUG_INTER_LINK
        std::clog << "Inter linking strucs of flo @ " << std::setfill('0')
                  << std::hex << std::setw(8)
                  << pe_.raw_to_virtual_address(flo.entry_point)
                  << " via reference @ " << std::setw(8)
                  << pe_.raw_to_virtual_address(ref) << " * "
                  << sd.struc->name() << '\n';
#endif
        auto const ref_flo = reflo_.get_flo_by_address(ref);
        assert(ref_flo);
        auto const &ref_flo_contexts = recontex_.get_contexts(*ref_flo);
        auto const &ref_instr = *ref_flo->get_instruction(ref);
        // Tail JMP have already return address on stack
        unsigned stack_offset = 8;
        if (ref_instr.mnemonic == ZYDIS_MNEMONIC_CALL) {
            // Where as CALL is yet to place return address on stack
            stack_offset = 0;
        }
        Address ref_sd_base = nullptr;
        auto ref_flo_domain = get_flo_domain(*ref_flo);
        if (ref_flo_domain) {
            for (auto const &context :
                 utils::multimap_values(ref_flo_contexts.equal_range(ref))) {
                auto rsp = context.get_register(ZYDIS_REGISTER_RSP);
                virt::Value arg = context.get_memory(
                    rsp->raw_address_value() + stack_offset + argument * 8,
                    8);
                if (!ref_flo->is_inside(arg.source())) {
                    inter_link_flo_strucs_via_stack(*ref_flo,
                                                    sd,
                                                    argument,
                                                    visited);
                    continue;
                }
#ifdef DEBUG_INTER_LINK
                std::clog << "Argument #" << argument + 1 << " source:\t";
                dumper.dump_instruction(
                    std::clog,
                    pe_.raw_to_virtual_address(arg.source()),
                    *ref_flo->get_instruction(arg.source()));
#endif
                if (auto new_ref_sd_base =
                        find_ref_sd_base(arg, *ref_flo_domain);
                    (new_ref_sd_base && new_ref_sd_base->source)
                    && (ref_sd_base == nullptr
                        || (new_ref_sd_base->source < ref_sd_base))) {
                    ref_sd_base = new_ref_sd_base->source;
                }
                else if (new_ref_sd_base && !new_ref_sd_base->source) {
                    inter_link_flo_strucs_via_register(
                        *ref_flo,
                        sd,
                        new_ref_sd_base->root_reg,
                        visited);
                }
            }
            if (ref_sd_base) {
                inter_link_flo_strucs(flo, sd, *ref_flo, ref_sd_base);
            }
        }
        else {
            // Flo might not have FloDomain
            // if it is a single-instruction Flo
            // let's try to deeper.
            inter_link_flo_strucs_via_stack(*ref_flo, sd, argument, visited);
        }
    }
}

void Restruc::inter_link_flo_strucs_via_register(
    Flo const &flo,
    StrucDomain const &sd,
    ZydisRegister base_reg,
    std::unordered_set<Address> &visited)
{
#ifdef DEBUG_INTER_LINK
    Dumper dumper;
#endif
    for (auto ref : flo.get_references()) {
        if (visited.contains(ref)) {
            continue;
        }
        visited.insert(ref);
#ifdef DEBUG_INTER_LINK
        std::clog << "Inter linking strucs of flo @ " << std::setfill('0')
                  << std::hex << std::setw(8)
                  << pe_.raw_to_virtual_address(flo.entry_point)
                  << " via reference @ " << std::setw(8)
                  << pe_.raw_to_virtual_address(ref) << " * "
                  << sd.struc->name() << '\n';
#endif
        auto const ref_flo = reflo_.get_flo_by_address(ref);
        assert(ref_flo);
        Address ref_sd_base = nullptr;
        auto const &ref_flo_contexts = recontex_.get_contexts(*ref_flo);
        auto ref_flo_domain = get_flo_domain(*ref_flo);
        if (ref_flo_domain) {
            for (auto const &context :
                 utils::multimap_values(ref_flo_contexts.equal_range(ref))) {
                if (auto val = context.get_register(base_reg); val) {
#ifdef DEBUG_INTER_LINK
                    std::clog << "Trying to find struc domain base for "
                              << ZydisRegisterGetString(base_reg) << ": ";
                    dumper.dump_value(std::clog, *val);
#endif
                    if (auto new_ref_sd_base =
                            find_ref_sd_base(*val, *ref_flo_domain);
                        (new_ref_sd_base && new_ref_sd_base->source)
                        && (ref_sd_base == nullptr
                            || (new_ref_sd_base->source < ref_sd_base))) {
                        ref_sd_base = new_ref_sd_base->source;
                    }
                    else if (new_ref_sd_base && !new_ref_sd_base->root_reg) {
                        inter_link_flo_strucs_via_register(
                            *ref_flo,
                            sd,
                            new_ref_sd_base->root_reg,
                            visited);
                    }
                }
            }
            if (ref_sd_base) {
                inter_link_flo_strucs(flo, sd, *ref_flo, ref_sd_base);
            }
        }
        else {
            // Flo might not have FloDomain
            // if it is a single-instruction Flo
            // let's try to deeper.
            inter_link_flo_strucs_via_register(*ref_flo, sd, base_reg, visited);
        }
    }
}

std::optional<Restruc::StrucDomainBase>
Restruc::find_ref_sd_base(virt::Value const &value,
                          FloDomain const &ref_flo_domain)
{
    if (auto it = ref_flo_domain.root_map.find(value);
        it != ref_flo_domain.root_map.end()) {
        return StrucDomainBase{ it->first.source(), it->second };
    }
    return std::nullopt;
}

ZydisRegister Restruc::find_ref_sd_base_reg(Address ref_sd_base,
                                            FloDomain const &ref_flo_domain)
{
    if (auto it = ref_flo_domain.base_map.find(ref_sd_base);
        it != ref_flo_domain.base_map.end()) {
        return it->second;
    }
    return ZYDIS_REGISTER_NONE;
}

void Restruc::inter_link_flo_strucs(Flo const &flo,
                                    StrucDomain const &sd,
                                    Flo const &ref_flo,
                                    Address ref_sd_base)
{
#ifdef DEBUG_INTER_LINK
    Dumper dumper;
    std::clog << "Reference Flo StructWrapper base:\n";
    dumper.dump_instruction(std::clog,
                            pe_.raw_to_virtual_address(ref_sd_base),
                            *ref_flo.get_instruction(ref_sd_base));
#endif
    auto const &ref_flo_domain = *get_flo_domain(ref_flo);
    auto const &ref_flo_contexts = recontex_.get_contexts(ref_flo);
    auto ref_sd_base_reg = find_ref_sd_base_reg(ref_sd_base, ref_flo_domain);
    if (ref_sd_base_reg == ZYDIS_REGISTER_NONE) {
        return;
    }
    for (auto const &context :
         utils::multimap_values(ref_flo_contexts.equal_range(ref_sd_base))) {
        if (auto reg = context.get_register(ref_sd_base_reg); reg) {
            if (auto it = ref_flo_domain.strucs.find(*reg);
                it != ref_flo_domain.strucs.end()) {
                auto &parent_sd = it->second;
                auto it_rel_instr =
                    parent_sd.relevant_instructions.find(ref_sd_base);
                if (it_rel_instr == parent_sd.relevant_instructions.end()) {
                    continue;
                }
                auto mem_op = get_memory_operand(*it_rel_instr->second);
                intptr_t offset = mem_op->mem.disp.value;
                if (!mem_op || offset < 0) {
                    continue;
                }
                auto &parent_struc = *parent_sd.struc;
#ifdef DEBUG_INTER_LINK
                std::clog << "Linking " << sd.struc->name() << " with "
                          << parent_struc.name() << '\n';
#endif
                {
                    std::scoped_lock<std::mutex> merge_lock(
                        merge_strucs_mutex_); // TODO: get rid of it
                    try_merge_struc_field_at_offset(
                        *sd.struc,
                        parent_struc,
                        offset,
                        [this](Struc const &dst, Struc const &src) {
#ifdef DEBUG_MERGE
                            std::clog << "Merged " << src.name() << " into "
                                      << dst.name() << '\n';
#endif
                            std::scoped_lock<std::mutex> modify_guard(
                                modify_access_strucs_mutex_);
                            strucs_.erase(src.name());
                        });
                }
                {
                    std::scoped_lock<std::recursive_mutex> modify_guard(
                        parent_struc.mutex());
                    parent_struc.add_pointer_field(offset, 1, sd.struc.get());
                }
            }
        }
    }
}

void Restruc::try_merge_struc_field_at_offset(
    Struc &dst,
    Struc const &src,
    size_t offset,
    Struc::MergeCallback merge_callback)
{
    if (&dst == &src) {
        return;
    }
    std::scoped_lock<std::recursive_mutex> modify_guard(src.mutex());
    for (auto it = std::reverse_iterator(src.fields().upper_bound(offset));
         it != src.fields().rend();
         ++it) {
        auto &src_field = it->second;
        auto src_field_offset = it->first;
        auto src_field_offset_end =
            src_field_offset + src_field.count() * src_field.size();
        if (src_field_offset_end <= offset) {
            break;
        }
        if (src_field.type() != Struc::Field::Type::Pointer
            || !src_field.struc() || src_field_offset % 8 != offset % 8) {
            continue;
        }
        dst.merge(*src_field.struc(), merge_callback);
    }
}

std::string Restruc::generate_struc_name(Flo const &flo,
                                         virt::Value const &value)
{
    std::ostringstream oss;
    oss << std::setfill('0') << std::hex << "rs_";
    if (value.source()) {
        oss << std::setw(8) << pe_.raw_to_virtual_address(value.source());
    }
    else {
        oss << std::setw(8) << pe_.raw_to_virtual_address(flo.entry_point)
            << '_' << value.raw_value();
    }
    return oss.str();
}

void Restruc::add_struc_field(Flo const &flo,
                              Address address,
                              Struc &struc,
                              ZydisDecodedInstruction const &instruction)
{
    auto mem_op = get_memory_operand(instruction);
    if (!mem_op) {
        return;
    }
    size_t offset = 0;
    if (mem_op->mem.disp.has_displacement) {
        if (mem_op->mem.disp.value < 0) {
            return;
        }
        offset = mem_op->mem.disp.value;
    }
    size_t count = get_field_count(flo, address, *mem_op);
    if (!mem_op->element_size) {
        if (!struc.has_field_at_offset(offset)) {
            // struc.add_pointer_field(offset, count);
        }
        return;
    }
    size_t size = mem_op->element_size / 8;
    switch (mem_op->element_type) {
    case ZYDIS_ELEMENT_TYPE_FLOAT16:
    case ZYDIS_ELEMENT_TYPE_FLOAT32:
    case ZYDIS_ELEMENT_TYPE_FLOAT64:
    case ZYDIS_ELEMENT_TYPE_FLOAT80:
        //
        struc.add_float_field(offset, size, count);
        break;
    case ZYDIS_ELEMENT_TYPE_UINT:
        //
        struc.add_int_field(offset, size, Struc::Field::Unsigned, count);
        break;
    default:
        //
        struc.add_int_field(offset, size, Struc::Field::Signed, count);
        break;
    }
}

ZydisDecodedOperand const *
Restruc::get_memory_operand(ZydisDecodedInstruction const &instruction)
{
    for (ZyanU8 i = 0; i < instruction.operand_count; i++) {
        auto const &op = instruction.operands[i];
        if (op.type == ZYDIS_OPERAND_TYPE_MEMORY
            && op.visibility == ZYDIS_OPERAND_VISIBILITY_EXPLICIT) {
            return &op; // (assume) explicit memory operand can be only one
        }
    }
    return nullptr;
}

// Returns count for Field by analyzing cycles (if any)
size_t Restruc::get_field_count(Flo const &flo,
                                Address address,
                                ZydisDecodedOperand const &mem_op)
{
    auto const &contexts = recontex_.get_contexts(flo);
    auto const &cycles = flo.get_cycles(address);
    size_t count = 1;
    if (cycles.empty() || mem_op.mem.index == ZYDIS_REGISTER_NONE) {
        return count;
    }
    for (auto const &cycle : cycles) {
        ZydisRegister exit_reg = ZYDIS_REGISTER_NONE;
        for (auto const &context :
             utils::multimap_values(contexts.equal_range(address))) {
            auto index = context.get_register(mem_op.mem.index);
            if (!index) {
                continue;
            }
            for (auto const &exit_context :
                 utils::multimap_values(contexts.equal_range(cycle->last))) {
                for (auto const &[er, ec] : cycle->exit_conditions) {
                    auto reg = exit_context.get_register(er);
                    if (!reg) {
                        continue;
                    }
                    if (index == *reg) {
                        exit_reg = er;
                        goto exit_reg_found;
                    }
                }
            }
        }
        continue;
    exit_reg_found:
        for (auto const &ec : utils::multimap_values(
                 cycle->exit_conditions.equal_range(exit_reg))) {
            auto const &op2 = ec.instruction->operands[1];
            if (ec.instruction->mnemonic == ZYDIS_MNEMONIC_CMP
                && is_less_than_jump(ec.jump)) {
                // TODO: refactor: create contexts helper,
                // which can extract all values for any operand type.
                switch (op2.type) {
                case ZYDIS_OPERAND_TYPE_IMMEDIATE:
                    if (!op2.imm.is_signed || op2.imm.value.s > 0) {
                        count = std::max(count, op2.imm.value.u);
                    }
                    break;
                case ZYDIS_OPERAND_TYPE_REGISTER:
                    for (auto const &context : utils::multimap_values(
                             contexts.equal_range(address))) {
                        if (auto value = context.get_register(op2.reg.value);
                            value) {
                            if (!value->is_symbolic()) {
                                count = std::max(count, value->value());
                            }
                        }
                    }
                    break;
                case ZYDIS_OPERAND_TYPE_MEMORY:
                    for (auto const &context : utils::multimap_values(
                             contexts.equal_range(address))) {
                        auto address =
                            Recontex::get_memory_address(op2, context)
                                .raw_address_value();
                        if (virt::Value value = context.get_memory(address, 8);
                            !value.is_symbolic()) {
                            count = std::max(count, value.value());
                        }
                    }
                    break;
                }
            }
        }
    }
    return count;
}

bool Restruc::is_less_than_jump(ZydisMnemonic mnemonic)
{
    switch (mnemonic) {
    case ZYDIS_MNEMONIC_JB:
    case ZYDIS_MNEMONIC_JBE:
    case ZYDIS_MNEMONIC_JL:
    case ZYDIS_MNEMONIC_JLE:
        //
        return true;
    default:
        //
        return false;
    }
}

void Restruc::dump(std::ostream &os)
{
    auto flags = os.flags();
    os << std::setfill('0');
    for (auto const &[name, struc] : strucs_) {
        struc->print(os);
        os << '\n';
    }
    os.flags(flags);
}
