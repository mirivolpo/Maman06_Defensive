
#include "../MessageCodec.h"
#include <iostream>

int main()
{
    ResponsePayloadClientId payload{};

    for (int i = 0; i < 16; i++)
    {
        payload.clientId[i] = i;
    }

    std::string result = MessageCodec::clientIdToHex(payload);

    std::string expected = "000102030405060708090a0b0c0d0e0f";

    if (result == expected)
    {
        std::cout << "Test passed!\n";
        return 0;
    }

    std::cout << "Test failed! Got: " << result << '\n';
    return 1;
}
