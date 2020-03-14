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

rstc::Restruc::Function::Function()
    : address(nullptr)
{
}

Restruc::Function::Function(ZydisDecoder const &decoder, Address address)
    : address(address)
{
    // TODO: analyze bounds
    // TODO: find jumps_outside_
    while (true) {
        ZydisDecodedInstruction instruction;
        ZYAN_THROW(ZydisDecoderDecodeBuffer(&decoder,
                                            address,
                                            ZYDIS_MAX_INSTRUCTION_LENGTH,
                                            &instruction));
        instructions_.push_back(instruction);
        Address next_address = address + instruction.length;
        if (instruction.mnemonic == ZYDIS_MNEMONIC_JMP) {
            Address dest = address + instruction.operands[0].imm.value.s;
            jumps_inside_.emplace(dest, Jump(address, dest));
            next_address = dest;
        }
        else if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL) {
            Address dest = address + instruction.operands[0].imm.value.s;
            calls_.emplace(dest, Call(address, dest, next_address));
        }
        else if (instruction.mnemonic == ZYDIS_MNEMONIC_RET) {
            if (jumps_inside_.find(next_address) == jumps_inside_.end()) {
                break;
            }
        }
        address = next_address;
    }
}

Restruc::Restruc(std::filesystem::path const &pe_path)
    : pe_(pe_path)
{
}

void Restruc::add_function(ZydisDecoder const &decoder, Address address)
{
    unvisited_functions_.insert(address);
    functions_.emplace(address, Function(decoder, address));
}

void Restruc::analyze()
{
    ZydisDecoder decoder;
    ZYAN_THROW(ZydisDecoderInit(&decoder,
                                ZYDIS_MACHINE_MODE_LONG_64,
                                ZYDIS_ADDRESS_WIDTH_64));

    add_function(decoder, pe_.get_entry_point());
    for (auto unvisited_function_address : unvisited_functions_) {
        auto &function = functions_[unvisited_function_address];
        for (auto [_, call] : function.get_calls()) {
            add_function(decoder, call.to);
        }
        for (auto [_, jump] : function.get_jumps_outside()) {
            add_function(decoder, jump.to);
        }
    }
}
