#include "restruc.hxx"

#include "dumper.hxx"
#include "scope_guard.hxx"
#include "utils/adapters.hxx"

#include <algorithm>
#include <iostream>
#include <iterator>

using namespace rstc;

//#define DEBUG_ANALYSIS_PROGRESS
//#define DEBUG_CONTEXT_PROPAGATION

static ZydisRegister const VOLATILE_REGISTERS[] = {
    ZYDIS_REGISTER_RAX,  ZYDIS_REGISTER_RCX,  ZYDIS_REGISTER_RDX,
    ZYDIS_REGISTER_R8,   ZYDIS_REGISTER_R9,   ZYDIS_REGISTER_R10,
    ZYDIS_REGISTER_R11,  ZYDIS_REGISTER_ZMM0, ZYDIS_REGISTER_ZMM1,
    ZYDIS_REGISTER_ZMM2, ZYDIS_REGISTER_ZMM3, ZYDIS_REGISTER_ZMM4,
    ZYDIS_REGISTER_ZMM5,
};

static ZydisRegister const NONVOLATILE_REGISTERS[] = {
    ZYDIS_REGISTER_RBX,   ZYDIS_REGISTER_RBP,   ZYDIS_REGISTER_RSP,
    ZYDIS_REGISTER_RDI,   ZYDIS_REGISTER_RSI,   ZYDIS_REGISTER_R12,
    ZYDIS_REGISTER_R13,   ZYDIS_REGISTER_R14,   ZYDIS_REGISTER_R15,
    ZYDIS_REGISTER_ZMM6,  ZYDIS_REGISTER_ZMM7,  ZYDIS_REGISTER_ZMM8,
    ZYDIS_REGISTER_ZMM9,  ZYDIS_REGISTER_ZMM10, ZYDIS_REGISTER_ZMM11,
    ZYDIS_REGISTER_ZMM12, ZYDIS_REGISTER_ZMM13, ZYDIS_REGISTER_ZMM14,
    ZYDIS_REGISTER_ZMM15,
};

#ifdef DEBUG_CONTEXT_PROPAGATION

void dump_register_value(std::ostream &os,
                         Dumper const &dumper,
                         Reflo &reflo,
                         Context const &context,
                         ZydisRegister reg)
{
    if (auto changed = context.get_register(reg); changed) {
        auto flo = reflo.get_flo_by_address(changed->source());
        if (flo) {
            if (!changed->is_symbolic()) {
                os << std::setfill('0') << std::hex << ' ' << std::setw(16)
                   << changed->value() << " \n";
            }
            else {
                os << std::setfill('0') << std::hex << '[' << std::setw(16)
                   << changed->symbol().id() << "]\n";
            }
        }
    }
}

#endif

Restruc::Restruc(Reflo &reflo)
    : reflo_(reflo)
    , pe_(reflo.get_pe())
    , max_analyzing_threads_(std::thread::hardware_concurrency())
{
}

void Restruc::analyze()
{
    for (auto const &[address, flo] : reflo_.get_flos()) {
        run_analysis(*flo);
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

void Restruc::run_analysis(Flo &flo)
{
    auto lock = std::unique_lock(analyzing_threads_mutex_);
    analyzing_threads_cv_.wait(lock, [this] {
        return analyzing_threads_count_ < max_analyzing_threads_;
    });
    ++analyzing_threads_count_;
    analyzing_threads_.emplace_back([this, &flo]() mutable {
        ScopeGuard decrement_analyzing_threads_count([this]() noexcept {
            --analyzing_threads_count_;
            analyzing_threads_cv_.notify_all();
        });
#ifdef DEBUG_ANALYSIS_PROGRESS
        std::clog << "Analyzing: " << std::dec << analyzing_threads_.size()
                  << '/' << std::dec << reflo_.get_flos().size() << ": "
                  << std::setfill('0') << std::setw(8) << std::hex
                  << pe_.raw_to_virtual_address(flo.entry_point) << '\n';
#endif
        propagate_contexts(flo,
                           make_flo_initial_contexts(flo),
                           flo.entry_point);
    });
}

void Restruc::wait_for_analysis()
{
    std::for_each(analyzing_threads_.begin(),
                  analyzing_threads_.end(),
                  [](std::thread &t) { t.join(); });
    analyzing_threads_.clear();
}

void Restruc::propagate_contexts(Flo &flo,
                                 Contexts contexts,
                                 Address address,
                                 Address end,
                                 std::unordered_map<Address, size_t> visited)
{
    bool new_basic_block = true;
    if (!end) {
        auto last_instr = flo.get_disassembly().rbegin();
        end = last_instr->first + last_instr->second->length;
    }
    // Visit visited instructions without going deeper.
    while (address && address < end && !contexts.empty()
           && visited[address] < 2) {
        bool reset_next_contexts = false;
        visited[address]++;
#ifdef DEBUG_CONTEXT_PROPAGATION
        DWORD va = pe_.raw_to_virtual_address(address);
#endif
        if (new_basic_block) {
            new_basic_block = false;
            flo.filter_contexts(address, contexts);
            if (contexts.empty()) {
                break;
            }
        }
        auto propagation_result =
            flo.propagate_contexts(address, std::move(contexts));
        contexts = std::move(propagation_result.new_contexts);
        auto const instr = propagation_result.instruction;
#ifdef DEBUG_CONTEXT_PROPAGATION
        std::clog << std::dec << std::setfill(' ') << std::setw(5)
                  << contexts.size() << "ctx ";
        if (instr) {
            Dumper dumper;
            dumper.dump_instruction(std::clog, va, *instr);
            // Read values
            for (size_t i = 0; i < instr->operand_count; i++) {
                auto const &op = instr->operands[i];
                if (!(op.actions & ZYDIS_OPERAND_ACTION_MASK_READ)) {
                    continue;
                }
                for (auto const &context : contexts) {
                    switch (op.type) {
                    case ZYDIS_OPERAND_TYPE_REGISTER:
                        if (op.visibility
                            == ZYDIS_OPERAND_VISIBILITY_EXPLICIT) {
                            dump_register_value(std::clog,
                                                dumper,
                                                reflo_,
                                                context,
                                                op.reg.value);
                        }
                        break;
                    case ZYDIS_OPERAND_TYPE_MEMORY:
                        if (op.mem.base != ZYDIS_REGISTER_NONE
                            && op.mem.base != ZYDIS_REGISTER_RIP) {
                            dump_register_value(std::clog,
                                                dumper,
                                                reflo_,
                                                context,
                                                op.mem.base);
                        }
                        if (op.mem.index != ZYDIS_REGISTER_NONE) {
                            dump_register_value(std::clog,
                                                dumper,
                                                reflo_,
                                                context,
                                                op.mem.index);
                        }
                    default: break;
                    }
                }
            }
        }
        else {
            std::clog << std::hex << std::setfill('0') << std::setw(8)
                      << pe_.raw_to_virtual_address(address) << '\n';
        }
#endif
        if (!instr || contexts.empty()) {
            break;
        }
        if (instr->mnemonic == ZYDIS_MNEMONIC_CALL) {
            Contexts next_contexts;
            update_contexts_after_unknown_call(contexts, address);
        }
        else if (auto unconditional_jump =
                     instr->mnemonic == ZYDIS_MNEMONIC_JMP;
                 unconditional_jump
                 || Flo::is_conditional_jump(instr->mnemonic)) {
            auto dsts =
                flo.get_jump_destinations(pe_, address, *instr, contexts);
            for (auto dst : dsts) {
                // Analyze only loops (inner backward jumps)
                if (dst >= address || !flo.is_inside(dst)) {
                    continue;
                }
                propagate_contexts(flo,
                                   make_child_contexts(contexts),
                                   dst,
                                   address,
                                   visited);
            }
            if (unconditional_jump) {
                break;
            }
            else {
                new_basic_block = true;
            }
            if (dsts.empty() && unconditional_jump) {
                reset_next_contexts = true;
            }
        }
        else if (instr->mnemonic == ZYDIS_MNEMONIC_RET) {
            reset_next_contexts = true;
        }
        address += instr->length;
        // Check if next instruction is inside,
        // if so set contexts from previous inner jump with current destination,
        // otherwise stop.
        if (reset_next_contexts) {
            if (!flo.is_inside(address)) {
                break;
            }
            auto jumps = utils::multimap_values(
                flo.get_inner_jumps().equal_range(address));
            assert(jumps.begin() != jumps.end());
#ifdef NDEBUG
            if (jumps.begin() == jumps.end()) {
                break;
            }
#endif
            auto src = std::prev(jumps.end())->src;
            auto jump_contexts =
                utils::multimap_values(flo.get_contexts().equal_range(src));
            contexts = make_child_contexts(jump_contexts);
        }
    }
}

Contexts Restruc::make_flo_initial_contexts(Flo &flo)
{
    auto c = Context(nullptr);
    c.set_register(ZYDIS_REGISTER_RSP,
                   virt::make_value(flo.entry_point, 0xFF10000000000000));
    Contexts contexts;
    contexts.emplace(std::move(c));
    return contexts;
}

void Restruc::update_contexts_after_unknown_call(Contexts &contexts,
                                                 Address caller)
{
    Contexts new_contexts;
    std::transform(contexts.begin(),
                   contexts.end(),
                   std::inserter(new_contexts, new_contexts.end()),
                   [caller](Context const &context) {
                       auto new_context = context.make_child();
                       // Reset vlatile registers
                       for (auto volatile_register : VOLATILE_REGISTERS) {
                           new_context.set_register(
                               volatile_register,
                               virt::make_symbolic_value(caller));
                       }
                       return new_context;
                   });
    contexts = std::move(new_contexts);
}

bool Restruc::instruction_has_memory_access(
    ZydisDecodedInstruction const &instr)
{
    return std::any_of(instr.operands,
                       instr.operands + instr.operand_count,
                       operand_has_memory_access);
}

bool Restruc::operand_has_memory_access(ZydisDecodedOperand const &op)
{
    return op.type == ZYDIS_OPERAND_TYPE_MEMORY
           && op.visibility == ZYDIS_OPERAND_VISIBILITY_EXPLICIT;
}

bool Restruc::instruction_has_nonstack_memory_access(
    ZydisDecodedInstruction const &instr)
{
    return std::any_of(instr.operands,
                       instr.operands + instr.operand_count,
                       operand_has_nonstack_memory_access);
}

bool Restruc::operand_has_nonstack_memory_access(ZydisDecodedOperand const &op)
{
    return op.type == ZYDIS_OPERAND_TYPE_MEMORY
           && op.visibility == ZYDIS_OPERAND_VISIBILITY_EXPLICIT
           && op.mem.base != ZYDIS_REGISTER_RSP
           && op.mem.index != ZYDIS_REGISTER_RSP;
}

bool Restruc::is_history_term_instr(ZydisDecodedInstruction const &instr)
{
    if (instr.mnemonic == ZYDIS_MNEMONIC_XOR) {
        auto const &dst = instr.operands[0];
        auto const &src = instr.operands[1];
        if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER
            && src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            return dst.reg.value == src.reg.value;
        }
    }
    return false;
}

void Restruc::debug(std::ostream &os)
{
    Dumper dumper;
    for (auto const &[entry_point, flo] : reflo_.get_flos()) {
        if (flo->get_contexts().empty()) {
            continue;
        }
        for (auto const &[address, instr] : flo->get_disassembly()) {
            if (!instruction_has_nonstack_memory_access(*instr)) {
                continue;
            }
            dump_instruction_history(os,
                                     dumper,
                                     address,
                                     *instr,
                                     flo->get_contexts(address));
            os << "-----------------------------------------\n";
        }
    }
}

void Restruc::dump_register_history(std::ostream &os,
                                    Dumper const &dumper,
                                    Context const &context,
                                    ZydisRegister reg,
                                    std::unordered_set<Address> &visited) const
{
    {
        if (auto changed = context.get_register(reg); changed) {
            auto flo = reflo_.get_flo_by_address(changed->source());
            if (flo && !visited.contains(changed->source())) {
                visited.emplace(changed->source());
                if (!changed->is_symbolic()) {
                    os << std::hex << ' ' << std::setw(16) << changed->value()
                       << "      \t";
                }
                else {
                    os << std::hex << '[' << std::setw(16)
                       << changed->symbol().id() << '+' << std::setw(4)
                       << changed->symbol().offset() << "]\t";
                }
                dump_instruction_history(
                    os,
                    dumper,
                    changed->source(),
                    *flo->get_disassembly().at(changed->source()),
                    flo->get_contexts(changed->source()),
                    visited);
                os << "---\n";
            }
        }
    }
}

void Restruc::dump_memory_history(std::ostream &os,
                                  Dumper const &dumper,
                                  Context const &context,
                                  ZydisDecodedOperand const &op,
                                  std::unordered_set<Address> &visited) const
{
    if (auto mem_addr = Flo::get_memory_address(op, context); mem_addr) {
        auto values = context.get_memory(*mem_addr, op.element_size / 8);
        std::unordered_set<Address> sources;
        for (auto const &value : values.container) {
            sources.emplace(value.source());
        }
        for (auto source : sources) {
            if (source == pe_.get_entry_point() || visited.contains(source)) {
                continue;
            }
            if (auto flo = reflo_.get_flo_by_address(source); flo) {
                visited.emplace(source);
                dump_instruction_history(os,
                                         dumper,
                                         source,
                                         *flo->get_disassembly().at(source),
                                         flo->get_contexts(source),
                                         visited);
            }
        }
    }
}

void Restruc::dump_instruction_history(
    std::ostream &os,
    Dumper const &dumper,
    Address address,
    ZydisDecodedInstruction const &instr,
    std::vector<Context const *> const &contexts,
    std::unordered_set<Address> visited) const
{
    visited.emplace(address);
    DWORD va = pe_.raw_to_virtual_address(address);
    dumper.dump_instruction(os, va, instr);
    if (is_history_term_instr(instr)) {
        return;
    }
    for (size_t i = 0; i < instr.operand_count; i++) {
        auto const &op = instr.operands[i];
        if (!(op.actions & ZYDIS_OPERAND_ACTION_MASK_READ)) {
            continue;
        }
        for (auto const &context : contexts) {
            switch (op.type) {
            case ZYDIS_OPERAND_TYPE_REGISTER:
                if (op.visibility == ZYDIS_OPERAND_VISIBILITY_EXPLICIT) {
                    dump_register_history(os,
                                          dumper,
                                          *context,
                                          op.reg.value,
                                          visited);
                }
                break;
            case ZYDIS_OPERAND_TYPE_MEMORY:
                if (op.mem.base != ZYDIS_REGISTER_NONE
                    && op.mem.base != ZYDIS_REGISTER_RIP) {
                    dump_register_history(os,
                                          dumper,
                                          *context,
                                          op.mem.base,
                                          visited);
                }
                if (op.mem.index != ZYDIS_REGISTER_NONE) {
                    dump_register_history(os,
                                          dumper,
                                          *context,
                                          op.mem.index,
                                          visited);
                }
                dump_memory_history(os, dumper, *context, op, visited);
                break;
            default: break;
            }
        }
    }
}
