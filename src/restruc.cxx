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
        if (infos_.find(flo->entry_point) == infos_.end()) {
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

Restruc::FloInfo *Restruc::get_flo_info(Flo const &flo)
{
    if (auto it = infos_.find(flo.entry_point); it != infos_.end()) {
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
    FloInfo flo_info;
    VirtValueGroups groups;
    auto const &disassembly = flo.get_disassembly();
    auto const &flo_contexts = recontex_.get_contexts(flo);
    for (auto const &[address, instruction] : disassembly) {
        for (ZyanU8 i = 0; i < instruction->operand_count; i++) {
            auto const &op = instruction->operands[i];
            if (op.visibility != ZYDIS_OPERAND_VISIBILITY_EXPLICIT) {
                continue;
            }
            if (op.type == ZYDIS_OPERAND_TYPE_REGISTER
                && op.actions & ZYDIS_OPERAND_ACTION_MASK_READ) {
                for (auto const &context : utils::multimap_values(
                         flo_contexts.equal_range(address))) {
#ifdef DEBUG_ANALYSIS
                    DWORD va = pe_.raw_to_virtual_address(address);
#endif
                    if (auto reg = context.get_register(op.reg.value); reg) {
#ifdef DEBUG_ANALYSIS
                        std::clog << "Saving root register for #" << std::hex
                                  << std::setw(8) << reg->raw_value() << '\t';
                        dumper.dump_instruction(std::clog, va, *instruction);
#endif
                        flo_info.root_map.emplace(*reg, op.reg.value);
                    }
                }
            }
            else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY
                     && op.mem.base != ZYDIS_REGISTER_NONE
                     && op.mem.base != ZYDIS_REGISTER_RIP
                     // TODO: also analyze stack
                     && op.mem.base != ZYDIS_REGISTER_RSP) {
                flo_info.base_map.emplace(address, op.mem.base);
                for (auto const &context : utils::multimap_values(
                         flo_contexts.equal_range(address))) {
                    if (auto reg = context.get_register(op.mem.base); reg) {
                        auto &group = groups[*reg];
                        group.relevant_instructions.emplace(address,
                                                            instruction.get());
                        if (group.base_reg == ZYDIS_REGISTER_NONE) {
                            // Assume this is root base register, because
                            // analysis starts from the beginning.
                            group.base_reg = op.mem.base;
                        }
                    }
                }
            }
        }
    }
    if (!groups.empty()) {
        create_flo_strucs(flo, flo_info, std::move(groups));
        intra_link_flo_strucs(flo, flo_contexts, flo_info);
    }
    if (!flo_info.empty()) {
        add_flo_info(flo, std::move(flo_info));
    }
}

void Restruc::create_flo_strucs(Flo &flo,
                                FloInfo &flo_info,
                                VirtValueGroups &&groups)
{
#ifdef DEBUG_ANALYSIS
    Dumper dumper;
    DWORD va = pe_.raw_to_virtual_address(flo.entry_point);
    if (groups.empty()) {
        return;
    }
    std::clog << std::setfill('0') << std::hex << std::setw(8)
              << pe_.raw_to_virtual_address(flo.entry_point) << ":\n";
#endif
    for (auto &&[value, sw] : groups) {
#ifdef DEBUG_ANALYSIS
        if (!value.is_symbolic()) {
            std::clog << ' ' << std::setfill('0') << std::hex << std::setw(16)
                      << value.value() << "      :\n";
        }
        else {
            std::clog << '[' << std::setfill('0') << std::hex << std::setw(16)
                      << value.symbol().id() << '+' << std::hex << std::setw(4)
                      << value.symbol().offset() << "]:\n";
        }
#endif
        sw.struc = std::make_unique<Struc>(generate_struc_name(flo, value));
        for (auto const [address, instruction] : sw.relevant_instructions) {
#ifdef DEBUG_ANALYSIS
            dumper.dump_instruction(std::clog,
                                    pe_.raw_to_virtual_address(address),
                                    *instruction);
#endif
            auto contexts = recontex_.get_contexts(flo, address);
            auto cycles = flo.get_cycles(address);
            add_struc_field(*sw.struc, contexts, *instruction, cycles);
        }
#ifdef DEBUG_ANALYSIS
        std::clog << '\n';
        sw.struc->print(std::clog);
        std::clog << '\n';
#endif
        flo_info.strucs.emplace(value.source(), std::move(sw));
    }
#ifdef DEBUG_ANALYSIS
    std::clog << '\n';
#endif
}

void Restruc::intra_link_flo_strucs(Flo &flo,
                                    Recontex::FloContexts const &flo_contexts,
                                    FloInfo &flo_info)
{
    auto &strucs = flo_info.strucs;
    if (strucs.size() < 2) {
        return;
    }
#ifdef DEBUG_INTRA_LINK
    Dumper dumper;
    std::clog << "Linking strucs...\n";
#endif
    for (auto &[address, sw] : flo_info.strucs) {
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
                    if (auto it = strucs.find(reg->source());
                        it != strucs.end()) {
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
                        parent_struc.set_struc_ptr(offset, sw.struc.get());
                    }
                }
            }
        }
    }
}

void Restruc::add_flo_info(Flo &flo, FloInfo &&flo_info)
{
    std::scoped_lock<std::mutex> add_strucs_guard(modify_access_infos_mutex_);
    auto [it, inserted] = infos_.emplace(flo.entry_point, std::move(flo_info));
    assert(inserted);
}

void Restruc::inter_link_flo_strucs(Flo &flo)
{
    auto &flo_info = infos_.at(flo.entry_point);
    if (flo_info.strucs.empty()) {
        return;
    }
#ifdef DEBUG_INTER_LINK
    DWORD va = pe_.raw_to_virtual_address(flo.entry_point);
    std::clog << "Inter linking strucs of flo @ " << std::setfill('0')
              << std::hex << std::setw(8) << va << '\n';
#endif
    auto const &flo_contexts = recontex_.get_contexts(flo);
    for (auto &[address, sw] : flo_info.strucs) {
        // If StrucWrapper hasn't "root" address, then
        // this StrucWrapper is based on register which
        // came from outside of this Flo.
        // Otherwise, it's a memory/stack-based StrucWrapper.
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
                    !address.is_symbolic()) {
                    auto argument =
                        Recontex::stack_argument_number(address.value());
                    inter_link_flo_strucs_via_stack(flo, sw, argument);
                }
            }
        }
        else {
            inter_link_flo_strucs_via_register(flo, sw);
        }
    }
}

void Restruc::inter_link_flo_strucs_via_stack(Flo const &flo,
                                              StrucWrapper const &sw,
                                              unsigned argument)
{
#ifdef DEBUG_INTER_LINK
    Dumper dumper;
#endif
    for (auto ref : flo.get_references()) {
        auto const ref_flo = reflo_.get_flo_by_address(ref);
#ifndef NDEBUG
        if (!ref_flo) {
            continue;
        }
#else
        assert(ref_flo);
#endif
        auto const &ref_flo_contexts = recontex_.get_contexts(*ref_flo);
        auto const &ref_instr = *ref_flo->get_instruction(ref);
        // Tail JMP have already return address on stack
        unsigned stack_offset = 8;
        if (ref_instr.mnemonic == ZYDIS_MNEMONIC_CALL) {
            // Where as CALL is yet to place return address on stack
            stack_offset = 0;
        }
        Address ref_sw_base = nullptr;
        auto ref_flo_info = get_flo_info(*ref_flo);
        if (ref_flo_info) {
            for (auto const &context :
                 utils::multimap_values(ref_flo_contexts.equal_range(ref))) {
                auto rsp = context.get_register(ZYDIS_REGISTER_RSP);
                virt::Value arg = context.get_memory(
                    rsp->raw_address_value() + stack_offset + argument * 8,
                    8);
                if (!ref_flo->is_inside(arg.source())) {
                    inter_link_flo_strucs_via_stack(*ref_flo, sw, argument);
                    continue;
                }
#ifdef DEBUG_INTER_LINK
                std::clog << "Argument #" << argument + 1 << " source:\t";
                dumper.dump_instruction(
                    std::clog,
                    pe_.raw_to_virtual_address(arg.source()),
                    *ref_flo->get_instruction(arg.source()));
#endif
                if (auto new_ref_sw_base = find_ref_sw_base(arg, *ref_flo_info);
                    ref_sw_base == nullptr
                    || (new_ref_sw_base && new_ref_sw_base < ref_sw_base)) {
                    ref_sw_base = new_ref_sw_base;
                }
            }
        }
        if (!ref_sw_base) {
            inter_link_flo_strucs_via_stack(*ref_flo, sw, argument);
            continue;
        }
        inter_link_flo_strucs(flo, sw, *ref_flo, ref_sw_base);
    }
}

void Restruc::inter_link_flo_strucs_via_register(Flo const &flo,
                                                 StrucWrapper const &sw)
{
#ifdef DEBUG_INTER_LINK
    Dumper dumper;
#endif
    for (auto ref : flo.get_references()) {
#ifdef DEBUG_INTER_LINK
        std::clog << "Inter linking strucs of flo @ " << std::setfill('0')
                  << std::hex << std::setw(8)
                  << pe_.raw_to_virtual_address(flo.entry_point)
                  << " via reference @ " << std::setw(8)
                  << pe_.raw_to_virtual_address(ref) << " * "
                  << sw.struc->name() << '\n';
#endif
        auto const ref_flo = reflo_.get_flo_by_address(ref);
#ifndef NDEBUG
        if (!ref_flo) {
            continue;
        }
#else
        assert(ref_flo);
#endif
        Address ref_sw_base = nullptr;
        auto const &ref_flo_contexts = recontex_.get_contexts(*ref_flo);
        auto ref_flo_info = get_flo_info(*ref_flo);
        if (ref_flo_info) {
            for (auto const &context :
                 utils::multimap_values(ref_flo_contexts.equal_range(ref))) {
                if (auto val = context.get_register(sw.base_reg); val) {
                    if (auto new_ref_sw_base =
                            find_ref_sw_base(*val, *ref_flo_info);
                        ref_sw_base == nullptr
                        || (new_ref_sw_base && new_ref_sw_base < ref_sw_base)) {
                        ref_sw_base = new_ref_sw_base;
                    }
                }
            }
        }
        if (!ref_sw_base) {
            inter_link_flo_strucs_via_register(*ref_flo, sw);
            continue;
        }
        inter_link_flo_strucs(flo, sw, *ref_flo, ref_sw_base);
    }
}

Address Restruc::find_ref_sw_base(virt::Value const &value,
                                  FloInfo const &ref_flo_info)
{
    
    if (auto it = ref_flo_info.root_map.find(value);
        it != ref_flo_info.root_map.end()) {
        return it->first.source();
    }
    return nullptr;
}

ZydisRegister Restruc::find_ref_sw_base_reg(Address ref_sw_base,
                                            FloInfo const &ref_flo_info)
{
    if (auto it = ref_flo_info.base_map.find(ref_sw_base);
        it != ref_flo_info.base_map.end()) {
        return it->second;
    }
    return ZYDIS_REGISTER_NONE;
}

void Restruc::inter_link_flo_strucs(Flo const &flo,
                                    StrucWrapper const &sw,
                                    Flo const &ref_flo,
                                    Address ref_sw_base)
{
#ifdef DEBUG_INTER_LINK
    Dumper dumper;
    std::clog << "Reference Flo StructWrapper base:\n";
    dumper.dump_instruction(std::clog,
                            pe_.raw_to_virtual_address(ref_sw_base),
                            *ref_flo.get_instruction(ref_sw_base));
#endif
    auto const &ref_flo_info = *get_flo_info(ref_flo);
    auto const &ref_flo_contexts = recontex_.get_contexts(ref_flo);
    auto ref_sw_base_reg = find_ref_sw_base_reg(ref_sw_base, ref_flo_info);
    if (ref_sw_base_reg == ZYDIS_REGISTER_NONE) {
        return;
    }
    for (auto const &context :
         utils::multimap_values(ref_flo_contexts.equal_range(ref_sw_base))) {
        if (auto reg = context.get_register(ref_sw_base_reg); reg) {
            auto range = ref_flo_info.strucs.equal_range(reg->source());
            for (auto it = range.first; it != range.second; ++it) {
                auto &parent_sw = it->second;
                auto it_rel_instr =
                    parent_sw.relevant_instructions.find(ref_sw_base);
                if (it_rel_instr == parent_sw.relevant_instructions.end()) {
                    continue;
                }
                auto mem_op = get_memory_operand(*it_rel_instr->second);
                intptr_t offset = mem_op->mem.disp.value;
                if (!mem_op || offset < 0) {
                    continue;
                }
                auto &parent_struc = *parent_sw.struc;
#ifdef DEBUG_INTER_LINK
                std::clog << "Linking " << sw.struc->name() << " with "
                          << parent_struc.name() << '\n';
#endif
                {
                    std::scoped_lock<std::mutex> notify_guard(
                        parent_struc.mutex());
                    for (auto const &field : utils::multimap_values(
                             parent_struc.fields().equal_range(offset))) {
                        if (field.type() == Struc::Field::Pointer && field.struc()) {
                            merge_strucs(*sw.struc, *field.struc());
                        }
                    }
                    parent_struc.set_struc_ptr(offset, sw.struc.get());
                }
            }
        }
    }
}

void Restruc::merge_strucs(Struc &dst, Struc const &src)
{
#ifdef DEBUG_MERGE
    std::clog << "Merging " << src.name() << " into " << dst.name() << '\n';
#endif
    for (auto const &[offset, field] : src.fields()) {
        dst.merge_fields(offset, field);
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

// Returns count for Field by analyzing cycles (if any)
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
    for (auto const &[flo_ep, flo_info] : infos_) {
        if (flo_info.strucs.empty()) {
            continue;
        }
        os << "// " << std::hex << std::setw(8)
           << pe_.raw_to_virtual_address(flo_ep) << ":\n";
        for (auto const &[_, sw] : flo_info.strucs) {
            sw.struc->print(os);
            os << '\n';
        }
    }
    os.flags(flags);
}
