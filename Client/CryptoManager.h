
#pragma once

#include <rsa.h>
#include <vector>
#include <cstdint>
#include <string>

class CryptoManager
{

public:
    void generateRSAKeys();

    std::vector<uint8_t> getPublicKeyBytes() const;

    std::vector<uint8_t> decryptAESKey(
        const std::vector<uint8_t> &encryptedKey) const;

    std::string getPrivateKeyBase64() const;

    void savePrivateKeyToFile(const std::string &filePath) const;

private:
    CryptoPP::RSA::PrivateKey privateKey_;
    CryptoPP::RSA::PublicKey publicKey_;
};
