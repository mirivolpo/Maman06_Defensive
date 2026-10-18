#include <boost/asio.hpp>
#include <aes.h>

#include <iostream>
#include <exception>
#include <cstring>
#include <Windows.h>

#include "Protocol.h"
#include "ConfigManager.h"
#include "NetworkClient.h"

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
    try
    {

        wchar_t exePath[MAX_PATH] = {};
        DWORD length = GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        if (length == 0 || length >= MAX_PATH)
        {
            std::cerr << "Error: Could not determine executable path\n";
            return 1;
        }

        std::filesystem::path configPath = std::filesystem::path(exePath).parent_path() / "transfer.json";

        ClientConfig config = ConfigManager::loadFromFile(configPath);

        std::cout << "Server IP: " << config.serverIp << '\n';
        std::cout << "Server Port: " << config.serverPort << '\n';
        std::cout << "Client Name: " << config.clientName << '\n';
        std::cout << "Number of files: " << config.filePaths.size() << '\n';

        NetworkClient networkClient;

        networkClient.connect(config.serverIp, config.serverPort);

        std::cout << "Connected to server successfully!\n";
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }

    return 0;
}