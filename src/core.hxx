#pragma once

#include <Zydis/Zydis.h>

#include <memory>

namespace rstc {

    using Byte = unsigned char;
    using Address = Byte const *;
    using Instruction = std::unique_ptr<ZydisDecodedInstruction>;

    template<typename I>
    struct PairRangeAdapter {
        std::pair<I, I> pair;
        PairRangeAdapter(std::pair<I, I> const &pair)
            : pair(pair)
        {
        }
        I begin() const { return pair.first; }
        I end() const { return pair.second; }
    };

    template<typename I>
    inline auto in_range(std::pair<I, I> const &pair)
    {
        return PairRangeAdapter<I>(pair);
    }

}
