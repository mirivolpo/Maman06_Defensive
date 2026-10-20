

#include <iostream>
#include <exception>
#include <filesystem>

#include "ConfigManager.h"
#include "ClientSession.h"

#include <Windows.h>

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

        ClientSession session(
            config,
            std::filesystem::path(exePath).parent_path());

        session.connectToServer();

        std::cout << "Connected to server successfully!\n";

        session.registerClient();

        session.sendPublicKey();
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }

    return 0;
}