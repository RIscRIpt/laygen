#pragma once

#include <Zydis/Zydis.h>

#include <memory>

namespace rstc {

    using Byte = unsigned char;
    using Address = Byte const *;
    using Instruction = std::unique_ptr<ZydisDecodedInstruction>;

}
