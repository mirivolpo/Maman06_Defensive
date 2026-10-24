#include "NetworkClient.h"

NetworkClient::NetworkClient()
    : socket_(ioContext_)
{
}

// Resolve the address and open a TCP connection to the configured server.
void NetworkClient::connect(const std::string &ip, uint16_t port)
{
    boost::asio::ip::tcp::resolver resolver(ioContext_);

    boost::asio::connect(
        socket_,
        resolver.resolve(ip, std::to_string(port)));
}

// Boost.Asio write() sends all supplied bytes or reports an error.
void NetworkClient::sendData(const std::vector<uint8_t> &data)
{
    boost::asio::write(
        socket_,
        boost::asio::buffer(data));
}

// Read exactly the requested number of bytes, even if TCP delivers them in parts.
std::vector<uint8_t> NetworkClient::receiveData(std::size_t size)
{
    std::vector<uint8_t> data(size);

    boost::asio::read(
        socket_,
        boost::asio::buffer(data));

    return data;
}