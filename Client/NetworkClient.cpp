#include "NetworkClient.h"

NetworkClient::NetworkClient()
    : socket_(ioContext_)
{
}

void NetworkClient::connect(const std::string &ip, uint16_t port)
{
    boost::asio::ip::tcp::resolver resolver(ioContext_);

    boost::asio::connect(
        socket_,
        resolver.resolve(ip, std::to_string(port)));
}

void NetworkClient::sendData(const std::vector<uint8_t> &data)
{
    boost::asio::write(
        socket_,
        boost::asio::buffer(data));
}

std::vector<uint8_t> NetworkClient::receiveData(std::size_t size)
{
    std::vector<uint8_t> data(size);

    boost::asio::read(
        socket_,
        boost::asio::buffer(data));

    return data;
}