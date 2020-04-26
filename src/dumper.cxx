#include "dumper.hxx"
#include "zyan_error.hxx"

using namespace rstc;

Dumper::Dumper()
{
    ZYAN_THROW(ZydisFormatterInit(&formatter_, ZYDIS_FORMATTER_STYLE_INTEL));
}

void Dumper::dump_flo(std::ostream &os, Flo const &flo, DWORD entry_point_va)
{
    char buffer[256];
    os << std::hex << std::setfill('0');
    os << std::setw(8) << entry_point_va << ":\n";
    for (auto const &[address, ctx_instr] : flo.get_disassembly()) {
        dump_instruction(os,
                         static_cast<DWORD>(address - flo.entry_point)
                             + entry_point_va,
                         ctx_instr.instruction);
    }
    os << '\n';
}

void Dumper::dump_instruction(std::ostream &os,
                              DWORD va,
                              Instruction const &instruction)
{
    char buffer[256];
    ZYAN_THROW(ZydisFormatterFormatInstruction(&formatter_,
                                               instruction.get(),
                                               buffer,
                                               sizeof(buffer),
                                               va));
    os << std::hex << std::setfill('0') << std::setw(8) << va << "    "
       << buffer << '\n';
}
