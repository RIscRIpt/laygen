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

static std::string generate_struc_name(virt::Value const &value)
{
    std::ostringstream oss;
    oss << "rs_" << std::setfill('0') << std::hex << std::setw(16)
        << value.raw_value();
    return oss.str();
}

static void add_struc_field(Struc &struc,
                            std::vector<Context const *> const &contexts,
                            ZydisDecodedInstruction const &instruction,
                            std::vector<Cycle const *> const &cycles)
{
    ZydisDecodedOperand const *mem_op = nullptr;
    for (ZyanU8 i = 0; i < instruction.operand_count; i++) {
        auto const &op = instruction.operands[i];
        if (op.type == ZYDIS_OPERAND_TYPE_MEMORY
            && op.visibility == ZYDIS_OPERAND_VISIBILITY_EXPLICIT) {
            mem_op = &op;
            break; // (assume) explicit memory operand can be only one
        }
    }
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
    size_t size = 8;
    if (mem_op->element_size) {
        size = mem_op->element_size / 8;
    }
    size_t count = 1;
    if (!cycles.empty() && mem_op->mem.index != ZYDIS_REGISTER_NONE) {
        for (auto const &cycle : cycles) {
            for (auto const &ec : cycle->exit_conditions) {
                auto op1 = ec.instruction->operands[0];
                auto op2 = ec.instruction->operands[1];
                if (op1.type != ZYDIS_OPERAND_TYPE_REGISTER
                    || op1.reg.value != mem_op->mem.index) {
                    continue;
                }
                switch (ec.instruction->mnemonic) {
                case ZYDIS_MNEMONIC_CMP:
                    switch (op2.type) {
                    case ZYDIS_OPERAND_TYPE_IMMEDIATE:
                        if (!op2.imm.is_signed || op2.imm.value.s > 0) {
                            count = max(count, op2.imm.value.u);
                        }
                        break;
                    case ZYDIS_OPERAND_TYPE_REGISTER:
                        for (auto const &context : contexts) {
                            if (auto value =
                                    context->get_register(op2.reg.value);
                                value) {
                                if (!value->is_symbolic()) {
                                    count = max(count, value->value());
                                }
                            }
                        }
                        break;
                    }
                    break;
                }
            }
        }
    }
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
        analyze_flo(flo);
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
    auto const &contexts = flo.get_contexts();
    auto address = flo.entry_point;
    Address end;
    {
        auto const &[end_addr, last_instr] = *disassembly.rbegin();
        end = end_addr + last_instr->length;
    }
    std::unordered_set<Address> visited;
#ifdef DEBUG_ANALYSIS
    Dumper dumper;
    DWORD va = pe_.raw_to_virtual_address(address);
#endif
    InstructionGroups groups;
    while (address < end) {
        visited.emplace(address);
        auto const &instruction = *disassembly.at(address);
        for (ZyanU8 i = 0; i < instruction.operand_count; i++) {
            auto const &op = instruction.operands[i];
            if (op.type != ZYDIS_OPERAND_TYPE_MEMORY) {
                continue;
            }
            if (op.mem.base == ZYDIS_REGISTER_NONE
                || op.mem.base == ZYDIS_REGISTER_RIP) {
                continue;
            }
            // TODO: also analyze stack
            if (op.mem.base == ZYDIS_REGISTER_RSP) {
                continue;
            }
            for (auto const &context :
                 utils::multimap_values(contexts.equal_range(address))) {
                if (auto reg = context.get_register(op.mem.base); reg) {
                    groups[*reg].push_back(address);
                }
            }
        }
        // TODO: analyze jumps
        address += instruction.length;
    }
#ifdef DEBUG_ANALYSIS
    if (!groups.empty()) {
        std::clog << std::setfill('0') << std::hex << std::setw(8)
                  << pe_.raw_to_virtual_address(flo.entry_point) << ":\n";
        for (auto const &[value, addresses] : groups) {
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
            Struc struc(generate_struc_name(value));
            for (auto const address : addresses) {
                auto const &instruction = *disassembly.at(address);
                dumper.dump_instruction(std::clog,
                                        pe_.raw_to_virtual_address(address),
                                        instruction);
                auto contexts = flo.get_contexts(address);
                auto cycles = flo.get_cycles(address);
                add_struc_field(struc, contexts, instruction, cycles);
            }
            std::clog << '\n';
            print_struc(std::clog, struc);
            std::clog << '\n';
        }
        std::clog << '\n';
    }
#endif
}

void Restruc::dump(std::ostream &os)
{
}
