#pragma once

#include <boost/asio.hpp>
#include <string>
#include <cstdint>
#include <vector>
#include <cstddef>

class NetworkClient
{
public:
    NetworkClient();

    void connect(const std::string &ip, uint16_t port);

    void sendData(const std::vector<uint8_t> &data);

    std::vector<uint8_t> receiveData(std::size_t size);

private:
    boost::asio::io_context ioContext_;
    boost::asio::ip::tcp::socket socket_;
};