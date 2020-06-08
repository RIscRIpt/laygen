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

//#define DEBUG_ANALYSIS
//#define DEBUG_INTRA_LINK
#define DEBUG_INTER_LINK

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
        if (strucs_.find(flo->entry_point) == strucs_.end()) {
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
    auto const &disassembly = flo.get_disassembly();
    auto const &flo_contexts = recontex_.get_contexts(flo);
    MemoryInstructionsGroups groups;
    for (auto const &[address, instruction] : disassembly) {
        for (ZyanU8 i = 0; i < instruction->operand_count; i++) {
            auto const &op = instruction->operands[i];
            if (op.visibility != ZYDIS_OPERAND_VISIBILITY_EXPLICIT
                || op.type != ZYDIS_OPERAND_TYPE_MEMORY
                || op.mem.base == ZYDIS_REGISTER_NONE
                || op.mem.base == ZYDIS_REGISTER_RIP
                // TODO: also analyze stack
                || op.mem.base == ZYDIS_REGISTER_RSP) {
                continue;
            }
            for (auto const &context :
                 utils::multimap_values(flo_contexts.equal_range(address))) {
                if (auto reg = context.get_register(op.mem.base); reg) {
                    auto &group = groups[*reg];
                    group.relevant_instructions.push_back(address);
                    if (group.base_root_reg == ZYDIS_REGISTER_NONE) {
                        // TODO: get real root
                        group.base_root_reg = op.mem.base;
                    }
                }
            }
        }
    }
    if (groups.empty()) {
        return;
    }
    FloInstructionsGroups flo_ig =
        create_flo_strucs(flo, std::move(groups));
    intra_link_flo_strucs(flo, flo_contexts, flo_ig);
    add_flo_strucs(flo, std::move(flo_ig));
}

Restruc::FloInstructionsGroups
Restruc::create_flo_strucs(Flo &flo, MemoryInstructionsGroups &&groups)
{
    FloInstructionsGroups flo_ig;
#ifdef DEBUG_ANALYSIS
    Dumper dumper;
    // DWORD va = pe_.raw_to_virtual_address(flo.entry_point);
#endif
    if (!groups.empty()) {
#ifdef DEBUG_ANALYSIS
        std::clog << std::setfill('0') << std::hex << std::setw(8)
                  << pe_.raw_to_virtual_address(flo.entry_point) << ":\n";
#endif
        for (auto &&[value, group] : groups) {
#ifdef DEBUG_ANALYSIS
            if (!value.is_symbolic()) {
                std::clog << ' ' << std::setfill('0') << std::hex
                          << std::setw(16) << value.value() << "      :\n";
            }
            else {
                std::clog << '[' << std::setfill('0') << std::hex
                          << std::setw(16) << value.symbol().id() << '+'
                          << std::hex << std::setw(4) << value.symbol().offset()
                          << "]:\n";
            }
#endif
            group.struc =
                std::make_unique<Struc>(generate_struc_name(flo, value));
            for (auto const address : group.relevant_instructions) {
                auto const &instruction = *flo.get_instruction(address);
#ifdef DEBUG_ANALYSIS
                dumper.dump_instruction(std::clog,
                                        pe_.raw_to_virtual_address(address),
                                        instruction);
#endif
                auto contexts = recontex_.get_contexts(flo, address);
                auto cycles = flo.get_cycles(address);
                add_struc_field(*group.struc, contexts, instruction, cycles);
            }
#ifdef DEBUG_ANALYSIS
            std::clog << '\n';
            struc->print(std::clog);
            std::clog << '\n';
#endif
            flo_ig.emplace(value.source(), std::move(group));
        }
#ifdef DEBUG_ANALYSIS
        std::clog << '\n';
#endif
    }
    return std::move(flo_ig);
}

void Restruc::intra_link_flo_strucs(Flo &flo,
                                    Recontex::FloContexts const &flo_contexts,
                                    FloInstructionsGroups &flo_ig)
{
    if (flo_ig.size() < 2) {
        return;
    }
#ifdef DEBUG_INTRA_LINK
    Dumper dumper;
    std::clog << "Linking strucs...\n";
#endif
    for (auto &[address, ig] : flo_ig) {
        if (!address) {
            continue;
        }
        auto const &instruction = *flo.get_instruction(address);
        if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV) {
            auto const &src = instruction.operands[1];
            if (src.type != ZYDIS_OPERAND_TYPE_MEMORY) {
                continue;
            }
            for (auto const &context :
                 utils::multimap_values(flo_contexts.equal_range(address))) {
                if (auto reg = context.get_register(src.mem.base); reg) {
                    if (auto it = flo_ig.find(reg->source());
                        it != flo_ig.end()) {
                        auto &parent_struc = *it->second.struc;
                        size_t offset = 0;
                        if (src.mem.disp.has_displacement) {
                            if (src.mem.disp.value < 0) {
                                continue;
                            }
                            offset = src.mem.disp.value;
                        }
#ifdef DEBUG_INTRA_LINK
                        std::clog << "Linking " << struc->name() << " with "
                                  << parent_struc.name() << '\n';
#endif
                        parent_struc.set_struc_ptr(offset, ig.struc.get());
                    }
                }
            }
        }
    }
}

void Restruc::add_flo_strucs(Flo &flo, FloInstructionsGroups &&flo_ig)
{
    std::scoped_lock<std::mutex> add_strucs_guard(modify_access_strucs_mutex_);
    auto [it, inserted] =
        strucs_.emplace(flo.entry_point, std::move(flo_ig));
    assert(inserted);
}

void Restruc::inter_link_flo_strucs(Flo &flo)
{
#ifdef DEBUG_INTER_LINK
    DWORD va = pe_.raw_to_virtual_address(flo.entry_point);
    std::clog << "Inter linking strucs of flo @ " << std::setfill('0')
              << std::hex << std::setw(8) << va << '\n';
#endif
    auto &flo_ig = strucs_.at(flo.entry_point);
    auto const &flo_contexts = recontex_.get_contexts(flo);
    for (auto &[address, ig] : flo_ig) {
        if (address) {
            auto const &instruction = *flo.get_instruction(address);
            auto const &src = instruction.operands[1];
            if (instruction.mnemonic != ZYDIS_MNEMONIC_MOV
                || src.type != ZYDIS_OPERAND_TYPE_MEMORY
                || !Recontex::points_to_stack(src.mem.base,
                                              address,
                                              flo_contexts)) {
                continue;
            }
            std::unordered_set<int> linked_arg;
            for (auto const &context :
                 utils::multimap_values(flo_contexts.equal_range(address))) {
                if (auto address = Recontex::get_memory_address(src, context);
                    address) {
                    assert(Recontex::points_to_stack(*address));
                    // TODO: get argument number
                    //inter_link_flo_strucs_via_stack(flo, ig);
                }
            }
        }
        else {
            inter_link_flo_strucs_via_register(flo, ig);
        }
    }
}

void Restruc::inter_link_flo_strucs_via_register(Flo &flo,
                                                 InstructionsGroup const &ig)
{
    for (auto const &ref : flo.get_references()) {
        auto const &ref_flo = reflo_.get_flo_by_address(ref);
#ifndef NDEBUG
        if (!ref_flo) {
            continue;
        }
#else
        assert(ref_flo);
#endif
        auto const &ref_flo_disasm = ref_flo->get_disassembly();
        auto const &ref_flo_contexts = recontex_.get_contexts(*ref_flo);
        FloInstructionsGroups *ref_flo_igs = nullptr;
        if (auto it = strucs_.find(ref_flo->entry_point); it != strucs_.end()) {
            ref_flo_igs = &it->second;
        }
        else {
            continue;
        }
        for (auto const &context :
             utils::multimap_values(ref_flo_contexts.equal_range(ref))) {
            if (auto reg = context.get_register(ig.base_root_reg); reg) {
                if (auto it = ref_flo_igs->find(reg->source());
                    it != ref_flo_igs->end()) {
                    auto &parent_struc = *it->second.struc;
#ifdef DEBUG_INTER_LINK
                    std::clog << "Linking " << ig.struc->name() << " with "
                              << parent_struc.name() << '\n';
#endif
                    parent_struc.set_struc_ptr(0, ig.struc.get());
                }
            }
        }
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

void Restruc::add_struc_field(Struc &struc,
                              std::vector<Context const *> const &contexts,
                              ZydisDecodedInstruction const &instruction,
                              std::vector<Cycle const *> const &cycles)
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
    size_t count = get_field_count(*mem_op, cycles, contexts);
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

size_t Restruc::get_field_count(ZydisDecodedOperand const &mem_op,
                                std::vector<Cycle const *> const &cycles,
                                std::vector<Context const *> const &contexts)
{
    size_t count = 1;
    if (cycles.empty() || mem_op.mem.index == ZYDIS_REGISTER_NONE) {
        return count;
    }
    for (auto const &cycle : cycles) {
        for (auto const &ec : utils::multimap_values(
                 cycle->exit_conditions.equal_range(mem_op.mem.index))) {
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
                    for (auto const &context : contexts) {
                        if (auto value = context->get_register(op2.reg.value);
                            value) {
                            if (!value->is_symbolic()) {
                                count = std::max(count, value->value());
                            }
                        }
                    }
                    break;
                case ZYDIS_OPERAND_TYPE_MEMORY:
                    for (auto const &context : contexts) {
                        auto address =
                            Recontex::get_memory_address(op2, context)
                                .raw_address_value();
                        if (virt::Value value = context->get_memory(address, 8);
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
    for (auto const &[flo_ep, flo_ig] : strucs_) {
        os << "// " << std::hex << std::setw(8)
           << pe_.raw_to_virtual_address(flo_ep) << ":\n";
        for (auto const &[_, ig] : flo_ig) {
            ig.struc->print(os);
            os << '\n';
        }
    }
    os.flags(flags);
}
