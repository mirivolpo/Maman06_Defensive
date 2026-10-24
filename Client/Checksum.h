
#pragma once

#include <cstdint>
#include <vector>

namespace Checksum
{
    // Updates the CRC state with the next chunk of file data.
    uint32_t updateCRC(
        uint32_t currentCRC,
        const std::vector<uint8_t> &chunk);

    // Adds the file length and returns the final POSIX cksum value.
    uint32_t finalizeCRC(
        uint32_t currentCRC,
        std::uintmax_t fileSize);
}
