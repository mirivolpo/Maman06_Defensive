
#include "CryptoManager.h"

#include <osrng.h>
#include <queue.h>
#include <stdexcept>
#include <base64.h>
#include <filters.h>
#include <fstream>

// Cryptographic key lengths required by the assignment protocol.
const unsigned int RSA_KEY_SIZE_BITS = 1024;
const std::size_t AES_KEY_SIZE_BYTES = 32;

// Generate an RSA key pair for registration and the initial key exchange.
void CryptoManager::generateRSAKeys()
{
    CryptoPP::AutoSeededRandomPool rng;

    privateKey_.GenerateRandomWithKeySize(rng, RSA_KEY_SIZE_BITS);
    publicKey_.Initialize(privateKey_.GetModulus(), privateKey_.GetPublicExponent());
}

// Export the public RSA key as DER bytes for request 826.
std::vector<uint8_t> CryptoManager::getPublicKeyBytes() const
{
    CryptoPP::ByteQueue queue;

    publicKey_.DEREncode(queue);

    std::vector<uint8_t> bytes(queue.CurrentSize());

    queue.Get(bytes.data(), bytes.size());

    return bytes;
}

// Decrypt the server-provided AES key with RSA-OAEP and validate its length.
std::vector<uint8_t> CryptoManager::decryptAESKey(
    const std::vector<uint8_t> &encryptedKey) const
{
    CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(privateKey_);

    if (encryptedKey.size() != decryptor.FixedCiphertextLength())
    {
        throw std::runtime_error("Invalid encrypted AES key size");
    }

    std::vector<uint8_t> decryptedKey(
        decryptor.MaxPlaintextLength(encryptedKey.size()));

    CryptoPP::AutoSeededRandomPool rng;

    CryptoPP::DecodingResult result = decryptor.Decrypt(
        rng,
        encryptedKey.data(),
        encryptedKey.size(),
        decryptedKey.data());

    if (!result.isValidCoding)
    {
        throw std::runtime_error("Failed to decrypt AES key");
    }

    if (result.messageLength != AES_KEY_SIZE_BYTES)
    {
        throw std::runtime_error("Invalid decrypted AES key size");
    }

    decryptedKey.resize(result.messageLength);

    return decryptedKey;
}

// Encode the private RSA key for storage as Base64 text.
std::string CryptoManager::getPrivateKeyBase64() const
{
    std::string base64;

    CryptoPP::Base64Encoder encoder(
        new CryptoPP::StringSink(base64), false);

    privateKey_.DEREncode(encoder);

    encoder.MessageEnd();

    return base64;
}

// Restore the original private key for a later reconnect.
void CryptoManager::loadPrivateKeyFromBase64(
    const std::string &base64)
{
    std::string der;

    CryptoPP::StringSource(
        base64,
        true,
        new CryptoPP::Base64Decoder(
            new CryptoPP::StringSink(der)));

    CryptoPP::StringSource source(der, true);

    privateKey_.BERDecode(source);
}

// Save the private RSA key in its Base64 representation .
void CryptoManager::savePrivateKeyToFile(const std::string &filePath) const
{
    std::ofstream file(filePath, std::ios::binary);

    if (!file)
    {
        throw std::runtime_error("Failed to open private key file");
    }

    file << getPrivateKeyBase64();

    if (!file)
    {
        throw std::runtime_error("Failed to write private key file");
    }

    file.close();

    if (!file)
    {
        throw std::runtime_error("Failed to close private key file");
    }
}

// Initialize a fresh CBC encryption state with the zero IV.
void CryptoManager::startFileEncryption(
    const std::vector<uint8_t> &aesKey)
{
    if (aesKey.size() != AES_KEY_SIZE_BYTES)
    {
        throw std::runtime_error("Invalid AES key size");
    }

    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = {};

    aesEncryptor_.SetKeyWithIV(
        aesKey.data(),
        aesKey.size(),
        iv,
        sizeof(iv));
}

// Encrypt a chunk with the current CBC state; only the last chunk receives padding.
std::vector<uint8_t> CryptoManager::encryptFileChunk(
    const std::vector<uint8_t> &chunk,
    bool isLastChunk)
{
    std::vector<uint8_t> paddedChunk = chunk;

    // PKCS#7 adds a full block when the final plaintext length is already aligned.
    if (isLastChunk)
    {
        std::size_t paddingSize =
            CryptoPP::AES::BLOCKSIZE -
            (paddedChunk.size() % CryptoPP::AES::BLOCKSIZE);

        paddedChunk.insert(
            paddedChunk.end(),
            paddingSize,
            static_cast<uint8_t>(paddingSize));
    }

    std::vector<uint8_t> encryptedChunk(paddedChunk.size());

    aesEncryptor_.ProcessData(
        encryptedChunk.data(),
        paddedChunk.data(),
        paddedChunk.size());

    return encryptedChunk;
}
