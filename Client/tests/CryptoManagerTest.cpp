
#include "../CryptoManager.h"
#include <iostream>

int main()
{
    CryptoManager crypto;

    crypto.generateRSAKeys();

    std::vector<uint8_t> publicKeyBytes = crypto.getPublicKeyBytes();

    std::cout << "Public key size: "
              << publicKeyBytes.size()
              << " bytes\n";

    return 0;
}
