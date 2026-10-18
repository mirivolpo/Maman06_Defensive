#pragma once
#include <cstdint>
#include <string>
#include <vector>

// Disable memory padding to ensure exact binary alignment with the Python server
#pragma pack(push, 1)


struct RequestHeader
{
    uint8_t clientId[16];
    uint8_t version;
    uint16_t code;
    uint32_t payloadSize;
};

// Payload for requests 825 (Registration) and 827 (Reconnect)
struct PayloadName
{
    char name[255];
};

// Payload for request 826 (Send Public Key)
struct PayloadPublicKey
{
    char name[255];
    uint8_t publicKey[160];
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

// Server response header (7 bytes)
struct ResponseHeader
{
    uint8_t version;
    uint16_t code;
    uint32_t payloadSize;
};

// Payload for server responses 1600, 1604, 1606 (and base for 1602, 1605)
struct ResponsePayloadClientId
{
    uint8_t clientId[16];
};

// Payload for server response 1603 (CRC Checksum)
struct ResponsePayload1603
{
    uint8_t clientId[16];
    uint32_t contentSize;
    char fileName[255];
    uint32_t crc;
};

#pragma pack(pop)