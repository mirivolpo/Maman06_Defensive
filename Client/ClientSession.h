
#pragma once

#include "ConfigManager.h"
#include "NetworkClient.h"
#include "Protocol.h"
#include "CryptoManager.h"

#include <vector>
#include <filesystem>
#include <fstream>

class ClientSession
{
public:
    ClientSession(
        const ClientConfig &config,
        const std::filesystem::path &executableDir);

    void connectToServer();
    void registerClient();
    void sendPublicKey();
    void saveClientInfo() const;
    void sendFiles();

private:
    ClientConfig config_;
    NetworkClient networkClient_;
    CryptoManager cryptoManager_;

    ResponsePayloadClientId clientId_{};

    std::vector<uint8_t> aesKey_;
    std::filesystem::path executableDir_;

    std::vector<uint8_t> readFileChunk(std::ifstream &file) const;

    void sendFile(const std::string &filePath);

    ResponsePayload1603 receiveFileResponse();
};
