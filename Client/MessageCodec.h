
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

}
