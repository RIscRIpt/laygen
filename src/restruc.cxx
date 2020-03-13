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

bool is_jump_mnemonic(ZydisMnemonic mnemonic)
{
    return false;
}

rstc::Restruc::Function::Function()
    : address(nullptr)
{
}

Restruc::Function::Function(ZydisDecoder const &decoder, BYTE *address)
    : address(address)
{
    // TODO: analyze bounds
    while (true) {
        ZydisDecodedInstruction instruction;
        ZYAN_THROW(ZydisDecoderDecodeBuffer(&decoder,
                                            address,
                                            ZYDIS_MAX_INSTRUCTION_LENGTH,
                                            &instruction));
        instructions_.push_back(instruction);
        if (is_jump_mnemonic(instruction.mnemonic)) {
            jumps_.emplace_back(address,
                                address + instruction.operands[0].imm.value.s);
        }
        else if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL) {
            calls_.emplace_back(address,
                                address + instruction.operands[0].imm.value.s);
        }
        // TODO: analyze jumps
        if (instruction.mnemonic == ZYDIS_MNEMONIC_RET) {
            break;
        }
        address += instruction.length;
    }
}

Restruc::Restruc(std::filesystem::path const &pe_path)
    : pe_(pe_path)
{
}

void Restruc::analyze()
{
    ZydisDecoder decoder;
    ZYAN_THROW(ZydisDecoderInit(&decoder,
                                ZYDIS_MACHINE_MODE_LONG_64,
                                ZYDIS_ADDRESS_WIDTH_64));

    unvisited_functions_.insert(pe_.get_entry_point());
    functions_.emplace(pe_.get_entry_point(),
                       Function(decoder, pe_.get_entry_point()));
    for (auto unvisited_function_address : unvisited_functions_) {
        auto &function = functions_[unvisited_function_address];
        for (auto call : function.get_calls()) {
            unvisited_functions_.insert(call.to);
            functions_.emplace(call.to, Function(decoder, call.to));
        }
    }
}
