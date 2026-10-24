#include "ConfigManager.h"
#include <fstream>
#include <stdexcept>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

// Loads transfer.json and validates the client configuration before use.
ClientConfig ConfigManager::loadFromFile(const std::filesystem::path &filePath)
{
    std::ifstream file(filePath);

    if (!file.is_open())
    {
        throw std::runtime_error("Could not open configuration file: " + filePath.filename().string());
    }

    boost::property_tree::ptree json;
    boost::property_tree::read_json(file, json);

    ClientConfig config;

    // Read server settings
    config.serverIp = json.get<std::string>("server.ip");

    int port = json.get<int>("server.port");

    if (port <= 0 || port > 65535)
    {
        throw std::runtime_error("Invalid server port");
    }

    config.serverPort = static_cast<uint16_t>(port);

    config.clientName = json.get<std::string>("server.client");

    if (config.serverIp.empty())
    {
        throw std::runtime_error("Server IP cannot be empty");
    }

    if (config.clientName.empty() || config.clientName.size() > 100)
    {
        throw std::runtime_error("Invalid client name length");
    }
    // Reject non-ASCII bytes because the protocol expects an ASCII client name.
    for (unsigned char ch : config.clientName)
    {
        if (ch == 0 || ch > 127)
        {
            throw std::runtime_error("Client name must contain valid ASCII characters");
        }
    }

    // Read the list of files
    for (const auto &item : json.get_child("files"))
    {
        config.filePaths.push_back(item.second.get_value<std::string>());
    }

    return config;
}