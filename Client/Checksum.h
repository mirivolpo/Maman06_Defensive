
#pragma once

#include <cstdint>
#include <vector>

namespace Checksum
{
    uint32_t updateCRC(
        uint32_t currentCRC,
        const std::vector<uint8_t>& chunk
    );

    uint32_t finalizeCRC(
        uint32_t currentCRC,
        std::uintmax_t fileSize
    );
}
