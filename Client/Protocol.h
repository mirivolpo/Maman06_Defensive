#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <cstddef>

const std::size_t CLIENT_ID_SIZE = 16;
const std::size_t CLIENT_NAME_SIZE = 255;

const uint8_t CLIENT_VERSION = 3;

// Request codes
const uint16_t REGISTER_REQUEST = 825;
const uint16_t SEND_PUBLIC_KEY_REQUEST = 826;
const uint16_t SEND_FILE_REQUEST = 828;

// Response codes
const uint16_t REGISTER_SUCCESS = 1600;
const uint16_t REGISTER_FAILURE = 1601;
const uint16_t PUBLIC_KEY_RESPONSE = 1602;
const uint16_t FILE_RECEIVED_RESPONSE = 1603;
const uint16_t GENERAL_ERROR = 1607;

// Key sizes
const std::size_t PUBLIC_KEY_SIZE = 160;
const std::size_t ENCRYPTED_AES_KEY_SIZE = 128;

// namespace ProtocolConstants
// {
//     inline constexpr uint8_t CLIENT_VERSION = 3;
//     inline constexpr uint16_t REGISTER_REQUEST = 825;

//     inline constexpr uint16_t REGISTER_SUCCESS = 1600;
//     inline constexpr uint16_t REGISTER_FAILURE = 1601;
//     inline constexpr uint16_t GENERAL_ERROR = 1607;

// }

// Disable memory padding to ensure exact binary alignment with the Python server
#pragma pack(push, 1)

struct RequestHeader
{
    uint8_t clientId[CLIENT_ID_SIZE];
    uint8_t version;
    uint16_t code;
    uint32_t payloadSize;
};

// Payload for requests 825 (Registration) and 827 (Reconnect)
struct PayloadName
{
    char name[CLIENT_NAME_SIZE];
};

// Payload for request 826 (Send Public Key)
struct PayloadPublicKey
{
    char name[CLIENT_NAME_SIZE];
    uint8_t publicKey[PUBLIC_KEY_SIZE];
};

// Payload header for request 828 (Send File)
struct PayloadFile
{
    uint32_t contentSize;
    uint32_t origFileSize;
    uint16_t packetNumber;
    uint16_t totalPackets;
    char fileName[255];
    // The encrypted file content will be sent immediately after this struct
};

struct ResponseHeader
{
    uint8_t version;
    uint16_t code;
    uint32_t payloadSize;
};

struct ResponsePayloadClientId
{
    uint8_t clientId[CLIENT_ID_SIZE];
};

struct ResponsePayload1602
{
    uint8_t clientId[CLIENT_ID_SIZE];
    uint8_t encryptedAesKey[ENCRYPTED_AES_KEY_SIZE];
};

struct ResponsePayload1603
{
    uint8_t clientId[CLIENT_ID_SIZE];
    uint32_t contentSize;
    char fileName[255];
    uint32_t crc;
};

#pragma pack(pop)

static_assert(sizeof(RequestHeader) == 23, "Invalid request header size");
static_assert(sizeof(ResponseHeader) == 7, "Invalid response header size");
static_assert(sizeof(PayloadName) == 255, "Invalid name payload size");
static_assert(sizeof(PayloadPublicKey) == 415, "Invalid public key payload size");
static_assert(sizeof(PayloadFile) == 267, "Invalid file payload header size");
static_assert(sizeof(ResponsePayloadClientId) == 16, "Invalid client ID payload size");
static_assert(sizeof(ResponsePayload1603) == 279, "Invalid CRC response payload size");
