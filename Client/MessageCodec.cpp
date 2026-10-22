
#include "MessageCodec.h"
#include "Protocol.h"

#include <cstring>
#include <stdexcept>
#include <limits>

namespace MessageCodec
{
    std::vector<uint8_t> buildRegistrationRequest(const std::string &clientName)
    {
        // Create the request header
        RequestHeader header{};

        header.version = CLIENT_VERSION;
        header.code = REGISTER_REQUEST;
        header.payloadSize = sizeof(PayloadName);

        // Create the request payload
        PayloadName payload{};
        clientName.copy(payload.name, sizeof(payload.name) - 1);

        // Allocate memory for the complete request
        std::vector<uint8_t> request(sizeof(header) + sizeof(payload));

        // Copy header and payload into the request
        std::memcpy(request.data(), &header, sizeof(header));
        std::memcpy(request.data() + sizeof(header), &payload, sizeof(payload));

        return request;
    }

    ResponseHeader parseResponseHeader(const std::vector<uint8_t> &data)
    {
        if (data.size() != sizeof(ResponseHeader))
        {
            throw std::runtime_error("Invalid response header size");
        }

        ResponseHeader header{};
        std::memcpy(&header, data.data(), sizeof(header));

        return header;
    }

    ResponsePayloadClientId parseClientIdPayload(const std::vector<uint8_t> &data)
    {
        if (data.size() != sizeof(ResponsePayloadClientId))
        {
            throw std::runtime_error("Invalid client ID payload size");
        }

        ResponsePayloadClientId payload{};
        std::memcpy(&payload, data.data(), sizeof(payload));

        return payload;
    }

    std::string clientIdToHex(const ResponsePayloadClientId &payload)
    {
        const char hexDigits[] = "0123456789abcdef";
        std::string result;

        for (uint8_t byte : payload.clientId)
        {
            result += hexDigits[byte / 16];
            result += hexDigits[byte % 16];
        }

        return result;
    }

    std::vector<uint8_t> buildPublicKeyRequest(
        const std::string &clientName,
        const ResponsePayloadClientId &clientId,
        const std::vector<uint8_t> &publicKeyBytes)
    {
        if (publicKeyBytes.size() != PUBLIC_KEY_SIZE)
        {
            throw std::runtime_error("Invalid public key size");
        }

        RequestHeader header{};

        std::memcpy(header.clientId, clientId.clientId, sizeof(header.clientId));

        header.version = CLIENT_VERSION;
        header.code = SEND_PUBLIC_KEY_REQUEST;
        header.payloadSize = sizeof(PayloadPublicKey);

        PayloadPublicKey payload{};

        clientName.copy(payload.name, sizeof(payload.name) - 1);

        std::memcpy(payload.publicKey, publicKeyBytes.data(), publicKeyBytes.size());

        std::vector<uint8_t> request(sizeof(header) + sizeof(payload));

        std::memcpy(request.data(), &header, sizeof(header));

        std::memcpy(request.data() + sizeof(header), &payload, sizeof(payload));

        return request;
    }

    ResponsePayload1602 parsePublicKeyResponse(
        const std::vector<uint8_t> &data)
    {
        if (data.size() != sizeof(ResponsePayload1602))
        {
            throw std::runtime_error("Invalid public key response payload size");
        }

        ResponsePayload1602 payload{};

        std::memcpy(&payload, data.data(), sizeof(payload));

        return payload;
    }

}

std::vector<uint8_t> MessageCodec::buildFileRequestPrefix(
    const ResponsePayloadClientId &clientId,
    const std::string &fileName,
    uint32_t originalFileSize,
    uint32_t encryptedFileSize,
    uint16_t packetNumber,
    uint16_t totalPackets)
{
    if (encryptedFileSize >
        std::numeric_limits<uint32_t>::max() - sizeof(PayloadFile))
    {
        throw std::runtime_error("File payload is too large");
    }

    RequestHeader header{};

    std::memcpy(
        header.clientId,
        clientId.clientId,
        sizeof(header.clientId));

    header.version = CLIENT_VERSION;
    header.code = SEND_FILE_REQUEST;
    header.payloadSize = sizeof(PayloadFile) + encryptedFileSize;

    PayloadFile payload{};

    payload.contentSize = encryptedFileSize;
    payload.origFileSize = originalFileSize;
    payload.packetNumber = packetNumber;
    payload.totalPackets = totalPackets;

    if (fileName.empty() ||
        fileName.size() >= sizeof(payload.fileName))
    {
        throw std::runtime_error("Invalid file name");
    }

    std::memcpy(
        payload.fileName,
        fileName.data(),
        fileName.size());

    std::vector<uint8_t> requestPrefix(
        sizeof(RequestHeader) + sizeof(PayloadFile));

    std::memcpy(
        requestPrefix.data(),
        &header,
        sizeof(header));

    std::memcpy(
        requestPrefix.data() + sizeof(header),
        &payload,
        sizeof(payload));

    return requestPrefix;
}

ResponsePayload1603 MessageCodec::parseFileResponse(
    const std::vector<uint8_t> &payloadBytes)
{
    if (payloadBytes.size() != sizeof(ResponsePayload1603))
    {
        throw std::runtime_error("Invalid file response size");
    }

    ResponsePayload1603 payload{};

    std::memcpy(
        &payload,
        payloadBytes.data(),
        sizeof(payload));

    return payload;
}
