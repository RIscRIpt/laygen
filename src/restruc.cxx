#include "restruc.hxx"

#include "zyan_error.hxx"

#include <cinttypes>
#include <cstdio>
#include <iostream>
#include <string>

using namespace rstc;

#define ZYAN_THROW(expr)               \
    do {                               \
        ZyanStatus _status = (expr);   \
        if (ZYAN_FAILED(_status)) {    \
            throw zyan_error(_status); \
        }                              \
    } while (0)

static bool is_conditional_jump(ZydisMnemonic mnemonic)
{
    switch (mnemonic) {
    case ZYDIS_MNEMONIC_JB:
    case ZYDIS_MNEMONIC_JBE:
    case ZYDIS_MNEMONIC_JCXZ:
    case ZYDIS_MNEMONIC_JECXZ:
    case ZYDIS_MNEMONIC_JKNZD:
    case ZYDIS_MNEMONIC_JKZD:
    case ZYDIS_MNEMONIC_JL:
    case ZYDIS_MNEMONIC_JLE:
    case ZYDIS_MNEMONIC_JMP:
    case ZYDIS_MNEMONIC_JNB:
    case ZYDIS_MNEMONIC_JNBE:
    case ZYDIS_MNEMONIC_JNL:
    case ZYDIS_MNEMONIC_JNLE:
    case ZYDIS_MNEMONIC_JNO:
    case ZYDIS_MNEMONIC_JNP:
    case ZYDIS_MNEMONIC_JNS:
    case ZYDIS_MNEMONIC_JNZ:
    case ZYDIS_MNEMONIC_JO:
    case ZYDIS_MNEMONIC_JP:
    case ZYDIS_MNEMONIC_JRCXZ:
    case ZYDIS_MNEMONIC_JS:
    case ZYDIS_MNEMONIC_JZ:
        // Jxx
        return true;
    case ZYDIS_MNEMONIC_LOOP:
    case ZYDIS_MNEMONIC_LOOPE:
    case ZYDIS_MNEMONIC_LOOPNE:
        // LOOPxx
        return true;
    }
    return false;
}

static void print_instruction(ZydisDecodedInstruction const &instruction)
{
    char buffer[256];
    ZydisFormatter formatter;
    ZYAN_THROW(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL));
    ZYAN_THROW(ZydisFormatterFormatInstruction(&formatter,
                                               &instruction,
                                               buffer,
                                               sizeof(buffer),
                                               0));
    std::cout << buffer << '\n';
}

Restruc::Function::Function()
    : entry_point(nullptr)
{
}

Restruc::Function::Function(ZydisDecoder const &decoder,
                            Address entry_point,
                            Address end)
    : entry_point(entry_point)
{
    // TODO: analyze bounds
    Address address = entry_point;
    while (address != nullptr) {
        ZydisDecodedInstruction instruction;
        ZYAN_THROW(ZydisDecoderDecodeBuffer(&decoder,
                                            address,
                                            ZYDIS_MAX_INSTRUCTION_LENGTH,
                                            &instruction));
#ifndef NDEBUG
        print_instruction(instruction);
#endif
        visit(address);
        instructions_.emplace(address, instruction);
        Address next_address = address + instruction.length;
        if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL) {
            // Assume calls always return (i.e. they are not no-return)
            Address dst = next_address + instruction.operands[0].imm.value.s;
            add_call(dst, address, next_address);
        }
        else if (instruction.mnemonic == ZYDIS_MNEMONIC_RET) {
            if (!is_inside_function(next_address)) {
                break;
            }
        }
        else if (instruction.mnemonic == ZYDIS_MNEMONIC_JMP
                 || is_conditional_jump(instruction.mnemonic)) {
            bool unconditional = instruction.mnemonic == ZYDIS_MNEMONIC_JMP;
            Address dst = next_address + instruction.operands[0].imm.value.s;
            auto type = get_jump_type(dst, address, next_address);
            add_jump(type, dst, address);
            if (unconditional) {
                if (type == Jump::Inner) {
                    next_address = dst;
                }
                else {
                    break;
                }
            }
            else {
                unvisited_.emplace(dst);
            }
        }
        promote_unknown_to_inner_jump(next_address);
        address = next_address;
    }
}

void Restruc::Function::promote_unknown_to_inner_jump(Address dst)
{
    if (auto jump = unknown_jumps_.find(dst); jump != unknown_jumps_.end()) {
        add_jump(Jump::Inner, dst, jump->second.src);
        unknown_jumps_.erase(jump);
    }
}

void Restruc::Function::visit(Address address)
{
    if (auto uv = unvisited_.find(address); uv != unvisited_.end()) {
        unvisited_.erase(uv);
    }
}

Restruc::Jump::Type
Restruc::Function::get_jump_type(Address dst, Address src, Address next_address)
{
    // If jumping with offset 0, i.e. no jump
    if (dst == next_address) {
        return Jump::Inner;
    }
    // If jump is first function instruction
    if (instructions_.size() == 1) {
        return Jump::Outer;
    }
    if (instructions_.find(dst) != instructions_.end()) {
        return Jump::Inner;
    }
    // If jumping above function entry-point
    if (instructions_.begin()->first > dst) {
        return Jump::Outer;
    }
    // TODO: handle more cases
    return Jump::Unknown;
}

void Restruc::Function::add_jump(Jump::Type type, Address dst, Address src)
{
    switch (type) {
    case Jump::Inner:
        inner_jumps_.emplace(dst, Jump(Jump::Inner, dst, src));
        break;
    case Jump::Outer:
        outer_jumps_.emplace(dst, Jump(Jump::Outer, dst, src));
        break;
    case Jump::Unknown:
        unknown_jumps_.emplace(dst, Jump(Jump::Unknown, dst, src));
        break;
    }
}

void Restruc::Function::add_call(Address dst, Address src, Address ret)
{
    calls_.emplace(src, Call(dst, src, ret));
}

bool Restruc::Function::is_inside_function(Address address)
{
    return instructions_.find(address) != instructions_.end()
           || inner_jumps_.find(address) != inner_jumps_.end();
}

Restruc::Restruc(std::filesystem::path const &pe_path)
    : pe_(pe_path)
{
}

void Restruc::safe_add_function(ZydisDecoder const &decoder,
                                Address address,
                                Address end)
{
    // Prevent recursive analysis
    if (functions_.find(address) != functions_.end()) {
        return;
    }
    functions_.emplace(address, Function(decoder, address, end));
    unanalyzed_functions_.push_back(address);
}

Restruc::Address Restruc::pop_unanalyzed_function()
{
    auto address = unanalyzed_functions_.front();
    unanalyzed_functions_.pop_front();
    return address;
}

void Restruc::analyze()
{
    ZydisDecoder decoder;
    ZYAN_THROW(ZydisDecoderInit(&decoder,
                                ZYDIS_MACHINE_MODE_LONG_64,
                                ZYDIS_ADDRESS_WIDTH_64));

    safe_add_function(decoder, pe_.get_entry_point(), nullptr);
    while (!unanalyzed_functions_.empty()) {
        auto &function = functions_[pop_unanalyzed_function()];
        for (auto [_, call] : function.get_calls()) {
            safe_add_function(decoder, call.dst, nullptr);
        }
        for (auto [_, jump] : function.get_outer_jumps()) {
            safe_add_function(decoder, jump.dst, nullptr);
        }
    }
}
