
#pragma once

#include "ConfigManager.h"
#include "NetworkClient.h"
#include "Protocol.h"
#include "CryptoManager.h"

#include <vector>
#include <filesystem>

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

private:
    ClientConfig config_;
    NetworkClient networkClient_;
    CryptoManager cryptoManager_;

    ResponsePayloadClientId clientId_{};

    std::vector<uint8_t> aesKey_;
    std::filesystem::path executableDir_;
};
