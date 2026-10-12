#include "ConfigManager.h"
#include <fstream>
#include <stdexcept>

ClientConfig ConfigManager::loadFromFile(const std::string &filePath)
{
    std::ifstream file(filePath);

    if (!file.is_open())
    {
        throw std::runtime_error("Could not open configuration file: " + filePath);
    }

    return ClientConfig{};
}