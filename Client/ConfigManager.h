#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <filesystem>

// Connection details, client identity, and file paths loaded from transfer.json.
struct ClientConfig
{
    std::string serverIp;
    uint16_t serverPort = 0;
    std::string clientName;
    std::vector<std::string> filePaths;
};

// Reads and validates the client configuration file.
class ConfigManager
{
public:
    static ClientConfig loadFromFile(const std::filesystem::path &filePath);
};