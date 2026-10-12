#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct ClientConfig
{
    std::string serverIp;
    uint16_t serverPort = 0;
    std::string clientName;
    std::vector<std::string> filePaths;
};

class ConfigManager
{
public:
    static ClientConfig loadFromFile(const std::string& filePath);
};