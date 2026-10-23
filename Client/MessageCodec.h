
#pragma once

#include <string>
#include <vector>
#include <cstdint>

#include "Protocol.h"

namespace MessageCodec
{
    std::vector<uint8_t> buildRegistrationRequest(const std::string &clientName);
    ResponseHeader parseResponseHeader(const std::vector<uint8_t> &data);

    ResponsePayloadClientId parseClientIdPayload(const std::vector<uint8_t> &data);

    std::string clientIdToHex(const ResponsePayloadClientId &payload);

    std::vector<uint8_t> buildPublicKeyRequest(
        const std::string &clientName,
        const ResponsePayloadClientId &clientId,
        const std::vector<uint8_t> &publicKeyBytes);

    ResponsePayload1602 parsePublicKeyResponse(
        const std::vector<uint8_t> &data);

    std::vector<uint8_t> buildFileRequestPrefix(
        const ResponsePayloadClientId &clientId,
        const std::string &fileName,
        uint32_t originalFileSize,
        uint32_t encryptedFileSize,
        uint16_t packetNumber,
        uint16_t totalPackets);

    ResponsePayload1603 parseFileResponse(
        const std::vector<uint8_t> &payloadBytes);

    std::vector<uint8_t> buildCRCRequest(
        const ResponsePayloadClientId &clientId,
        uint16_t code,
        const std::string &fileName);

    std::vector<uint8_t> buildReconnectRequest(
        const ResponsePayloadClientId &clientId,
        const std::string &clientName);

    ResponsePayloadClientId hexToClientId(const std::string &hex);

}
