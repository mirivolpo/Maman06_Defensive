
#include "ClientSession.h"
#include "MessageCodec.h"

#include <stdexcept>
#include <iostream>
#include <cstring>
#include <fstream>

ClientSession::ClientSession(
    const ClientConfig &config,
    const std::filesystem::path &executableDir)
    : config_(config),
      executableDir_(executableDir)
{
}

void ClientSession::connectToServer()
{
    networkClient_.connect(config_.serverIp, config_.serverPort);
}

void ClientSession::registerClient()
{
    for (int attempt = 1; attempt <= 4; ++attempt)
    {
        std::vector<uint8_t> request =
            MessageCodec::buildRegistrationRequest(config_.clientName);

        networkClient_.sendData(request);

        std::vector<uint8_t> responseHeaderData =
            networkClient_.receiveData(sizeof(ResponseHeader));

        ResponseHeader responseHeader =
            MessageCodec::parseResponseHeader(responseHeaderData);

        if (responseHeader.payloadSize > sizeof(ResponsePayloadClientId))
        {
            throw std::runtime_error("Invalid registration response payload size");
        }

        std::vector<uint8_t> responsePayloadData =
            networkClient_.receiveData(responseHeader.payloadSize);

        if (responseHeader.code == REGISTER_SUCCESS)
        {
            ResponsePayloadClientId clientIdPayload =
                MessageCodec::parseClientIdPayload(responsePayloadData);
            clientId_ = clientIdPayload;

            std::string clientIdHex = MessageCodec::clientIdToHex(clientIdPayload);

            cryptoManager_.generateRSAKeys();

            cryptoManager_.savePrivateKeyToFile(
                (executableDir_ / "priv.key").string());

            saveClientInfo();

            std::cout << "Client registered successfully! ID: "
                      << clientIdHex << '\n';
            return;
        }

        else if (responseHeader.code == REGISTER_FAILURE ||
                 responseHeader.code == GENERAL_ERROR)
        {
            std::cerr << "server responded with an error\n";
        }

        else
        {
            throw std::runtime_error("Unexpected registration response code");
        }
    }

    throw std::runtime_error("Fatal: Registration failed after 4 attempts");
}

void ClientSession::sendPublicKey()
{
    std::vector<uint8_t> publicKeyBytes = cryptoManager_.getPublicKeyBytes();

    std::vector<uint8_t> request = MessageCodec::buildPublicKeyRequest(
        config_.clientName,
        clientId_,
        publicKeyBytes);

    networkClient_.sendData(request);

    std::vector<uint8_t> responseHeaderData =
        networkClient_.receiveData(sizeof(ResponseHeader));

    ResponseHeader responseHeader =
        MessageCodec::parseResponseHeader(responseHeaderData);

    if (responseHeader.code == GENERAL_ERROR)
    {
        throw std::runtime_error("Server failed to process public key");
    }

    if (responseHeader.code != PUBLIC_KEY_RESPONSE)
    {
        throw std::runtime_error("Unexpected public key response code");
    }

    if (responseHeader.payloadSize !=
        sizeof(ResponsePayloadClientId) + ENCRYPTED_AES_KEY_SIZE)
    {
        throw std::runtime_error("Invalid public key response payload size");
    }

    std::vector<uint8_t> responsePayloadData =
        networkClient_.receiveData(responseHeader.payloadSize);

    ResponsePayload1602 payload =
        MessageCodec::parsePublicKeyResponse(responsePayloadData);

    if (std::memcmp(payload.clientId, clientId_.clientId, sizeof(clientId_.clientId)) != 0)
    {
        throw std::runtime_error("Client ID mismatch in server response");
    }

    std::vector<uint8_t> encryptedKey(
        payload.encryptedAesKey,
        payload.encryptedAesKey + sizeof(payload.encryptedAesKey));

    aesKey_ = cryptoManager_.decryptAESKey(encryptedKey);
}

void ClientSession::saveClientInfo() const
{
    std::filesystem::path tempPath = executableDir_ / "me.info.tmp";

    std::ofstream file(tempPath, std::ios::binary | std::ios::trunc);

    if (!file)
    {
        throw std::runtime_error("Failed to open client info file");
    }

    file << config_.clientName << '\n';

    file << MessageCodec::clientIdToHex(clientId_) << '\n';

    file << cryptoManager_.getPrivateKeyBase64() << '\n';

    if (!file)
    {
        throw std::runtime_error("Failed to write client info file");
    }

    file.close();

    if (!file)
    {
        throw std::runtime_error("Failed to close client info file");
    }

    std::filesystem::path finalPath = executableDir_ / "me.info";

    if (std::filesystem::exists(finalPath))
    {
        throw std::runtime_error("Client info file already exists");
    }

    std::filesystem::rename(tempPath, finalPath);
}
