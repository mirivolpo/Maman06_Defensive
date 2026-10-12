#include <boost/asio.hpp>
#include <aes.h>
#include "Protocol.h"
#include "ConfigManager.h"

// Verify protocol structure sizes
static_assert(sizeof(RequestHeader) == 23, "Invalid request header size");
static_assert(sizeof(ResponseHeader) == 7, "Invalid response header size");
static_assert(sizeof(PayloadName) == 255, "Invalid name payload size");
static_assert(sizeof(PayloadPublicKey) == 415, "Invalid public key payload size");
static_assert(sizeof(PayloadFile) == 267, "Invalid file payload header size");
static_assert(sizeof(ResponsePayloadClientId) == 16, "Invalid client ID payload size");
static_assert(sizeof(ResponsePayload1603) == 279, "Invalid CRC response payload size");

int main()
{
    return 0;
}