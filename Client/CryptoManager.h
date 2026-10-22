
#pragma once

#include <rsa.h>
#include <vector>
#include <cstdint>
#include <string>
#include <aes.h>
#include <modes.h>

class CryptoManager
{

public:
    void generateRSAKeys();

    std::vector<uint8_t> getPublicKeyBytes() const;

    std::vector<uint8_t> decryptAESKey(
        const std::vector<uint8_t> &encryptedKey) const;

    std::string getPrivateKeyBase64() const;

    void savePrivateKeyToFile(const std::string &filePath) const;

    void startFileEncryption(const std::vector<uint8_t> &aesKey);

    std::vector<uint8_t> encryptFileChunk(
        const std::vector<uint8_t> &chunk,
        bool isLastChunk);

private:
    CryptoPP::RSA::PrivateKey privateKey_;
    CryptoPP::RSA::PublicKey publicKey_;

    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption aesEncryptor_;
};
