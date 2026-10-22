
#include "ClientSession.h"
#include "MessageCodec.h"
#include "Checksum.h"

#include <stdexcept>
#include <iostream>
#include <cstring>
#include <fstream>
#include <limits>
#include <cstdint>

const std::size_t FILE_CHUNK_SIZE = 2048;

ClientSession::ClientSession(
    const ClientConfig &config,
    const std::filesystem::path &executableDir)
    : config_(config),
      executableDir_(executableDir)
{
}

void ClientSession::connectToServer()
{
    networkClient_.connect(config_.serverIp, config_.serverPort);
}

void ClientSession::registerClient()
{
    for (int attempt = 1; attempt <= 4; ++attempt)
    {
        std::vector<uint8_t> request =
            MessageCodec::buildRegistrationRequest(config_.clientName);

        networkClient_.sendData(request);

        std::vector<uint8_t> responseHeaderData =
            networkClient_.receiveData(sizeof(ResponseHeader));

        ResponseHeader responseHeader =
            MessageCodec::parseResponseHeader(responseHeaderData);

        if (responseHeader.payloadSize > sizeof(ResponsePayloadClientId))
        {
            throw std::runtime_error("Invalid registration response payload size");
        }

        std::vector<uint8_t> responsePayloadData =
            networkClient_.receiveData(responseHeader.payloadSize);

        if (responseHeader.code == REGISTER_SUCCESS)
        {
            ResponsePayloadClientId clientIdPayload =
                MessageCodec::parseClientIdPayload(responsePayloadData);
            clientId_ = clientIdPayload;

            std::string clientIdHex = MessageCodec::clientIdToHex(clientIdPayload);

            cryptoManager_.generateRSAKeys();

            cryptoManager_.savePrivateKeyToFile(
                (executableDir_ / "priv.key").string());

            saveClientInfo();

            std::cout << "Client registered successfully! ID: "
                      << clientIdHex << '\n';
            return;
        }

        else if (responseHeader.code == REGISTER_FAILURE ||
                 responseHeader.code == GENERAL_ERROR)
        {
            std::cerr << "server responded with an error\n";
        }

        else
        {
            throw std::runtime_error("Unexpected registration response code");
        }
    }

    throw std::runtime_error("Fatal: Registration failed after 4 attempts");
}

void ClientSession::sendPublicKey()
{
    std::vector<uint8_t> publicKeyBytes = cryptoManager_.getPublicKeyBytes();

    std::vector<uint8_t> request = MessageCodec::buildPublicKeyRequest(
        config_.clientName,
        clientId_,
        publicKeyBytes);

    networkClient_.sendData(request);

    std::vector<uint8_t> responseHeaderData =
        networkClient_.receiveData(sizeof(ResponseHeader));

    ResponseHeader responseHeader =
        MessageCodec::parseResponseHeader(responseHeaderData);

    if (responseHeader.code == GENERAL_ERROR)
    {
        throw std::runtime_error("Server failed to process public key");
    }

    if (responseHeader.code != PUBLIC_KEY_RESPONSE)
    {
        throw std::runtime_error("Unexpected public key response code");
    }

    if (responseHeader.payloadSize !=
        sizeof(ResponsePayloadClientId) + ENCRYPTED_AES_KEY_SIZE)
    {
        throw std::runtime_error("Invalid public key response payload size");
    }

    std::vector<uint8_t> responsePayloadData =
        networkClient_.receiveData(responseHeader.payloadSize);

    ResponsePayload1602 payload =
        MessageCodec::parsePublicKeyResponse(responsePayloadData);

    if (std::memcmp(payload.clientId, clientId_.clientId, sizeof(clientId_.clientId)) != 0)
    {
        throw std::runtime_error("Client ID mismatch in server response");
    }

    std::vector<uint8_t> encryptedKey(
        payload.encryptedAesKey,
        payload.encryptedAesKey + sizeof(payload.encryptedAesKey));

    aesKey_ = cryptoManager_.decryptAESKey(encryptedKey);
}

void ClientSession::saveClientInfo() const
{
    std::filesystem::path tempPath = executableDir_ / "me.info.tmp";

    std::ofstream file(tempPath, std::ios::binary | std::ios::trunc);

    if (!file)
    {
        throw std::runtime_error("Failed to open client info file");
    }

    file << config_.clientName << '\n';

    file << MessageCodec::clientIdToHex(clientId_) << '\n';

    file << cryptoManager_.getPrivateKeyBase64() << '\n';

    if (!file)
    {
        throw std::runtime_error("Failed to write client info file");
    }

    file.close();

    if (!file)
    {
        throw std::runtime_error("Failed to close client info file");
    }

    std::filesystem::path finalPath = executableDir_ / "me.info";

    if (std::filesystem::exists(finalPath))
    {
        throw std::runtime_error("Client info file already exists");
    }

    std::filesystem::rename(tempPath, finalPath);
}

std::vector<uint8_t> ClientSession::readFileChunk(
    std::ifstream &file) const
{

    std::vector<uint8_t> chunk(FILE_CHUNK_SIZE);

    file.read(
        reinterpret_cast<char *>(chunk.data()),
        FILE_CHUNK_SIZE);

    std::streamsize bytesRead = file.gcount();

    chunk.resize(static_cast<std::size_t>(bytesRead));

    if (file.bad() || (file.fail() && !file.eof()))
    {
        throw std::runtime_error("Failed to read file chunk");
    }

    return chunk;
}

void ClientSession::sendFiles()
{
    for (const std::string &filePath : config_.filePaths)
    {
        sendFile(filePath);
    }
}

void ClientSession::sendFile(const std::string &filePath)
{
    const int MAX_ATTEMPTS = 4;

    std::string fileName =
        std::filesystem::path(filePath).filename().string();

    for (int attempt = 1; attempt <= MAX_ATTEMPTS; ++attempt)
    {
        if (sendFileAttempt(filePath))
        {
            std::vector<uint8_t> request =
                MessageCodec::buildCRCRequest(
                    clientId_,
                    CRC_VALID_REQUEST,
                    fileName);

            networkClient_.sendData(request);
            receiveCRCConfirmation();

            return;
        }

        uint16_t code = (attempt < MAX_ATTEMPTS)
                            ? CRC_INVALID_RETRY_REQUEST
                            : CRC_INVALID_ABORT_REQUEST;

        std::vector<uint8_t> request =
            MessageCodec::buildCRCRequest(
                clientId_,
                code,
                fileName);

        networkClient_.sendData(request);

        if (code == CRC_INVALID_ABORT_REQUEST)
        {
            receiveCRCConfirmation();

            throw std::runtime_error(
                "CRC validation failed after 4 attempts: " + fileName);
        }
    }
}

bool ClientSession::sendFileAttempt(const std::string &filePath)
{

    std::ifstream file(filePath, std::ios::binary);

    if (!file)
    {
        throw std::runtime_error("Failed to open file: " + filePath);
    }

    std::uintmax_t originalFileSize =
        std::filesystem::file_size(filePath);

    std::uintmax_t paddingSize =
        CryptoPP::AES::BLOCKSIZE -
        (originalFileSize % CryptoPP::AES::BLOCKSIZE);

    std::uintmax_t encryptedFileSize =
        originalFileSize + paddingSize;

    if (originalFileSize > std::numeric_limits<uint32_t>::max() ||
        encryptedFileSize > std::numeric_limits<uint32_t>::max())
    {
        throw std::runtime_error(
            "File is too large for the protocol: " + filePath);
    }

    std::string fileName =
        std::filesystem::path(filePath).filename().string();

    std::vector<uint8_t> requestPrefix =
        MessageCodec::buildFileRequestPrefix(
            clientId_,
            fileName,
            static_cast<uint32_t>(originalFileSize),
            static_cast<uint32_t>(encryptedFileSize),
            1,
            1);

    networkClient_.sendData(requestPrefix);

    uint32_t crc = sendEncryptedFileContent(
        file,
        originalFileSize);

    ResponsePayload1603 response = receiveFileResponse();

    validateFileResponse(
        response,
        fileName,
        static_cast<uint32_t>(encryptedFileSize));

    return crc == response.crc;
}

uint32_t ClientSession::sendEncryptedFileContent(
    std::ifstream &file,
    std::uintmax_t originalFileSize)
{
    cryptoManager_.startFileEncryption(aesKey_);

    uint32_t crc = 0;

    while (true)
    {
        std::vector<uint8_t> chunk = readFileChunk(file);

        crc = Checksum::updateCRC(crc, chunk);

        bool isLastChunk =
            chunk.empty() ||
            file.peek() == std::char_traits<char>::eof();

        std::vector<uint8_t> encryptedChunk =
            cryptoManager_.encryptFileChunk(chunk, isLastChunk);

        networkClient_.sendData(encryptedChunk);

        if (isLastChunk)
        {
            break;
        }
    }

    return Checksum::finalizeCRC(crc, originalFileSize);
}

void ClientSession::validateFileResponse(
    const ResponsePayload1603 &response,
    const std::string &fileName,
    uint32_t encryptedFileSize) const
{
    if (std::memcmp(
            response.clientId,
            clientId_.clientId,
            sizeof(response.clientId)) != 0)
    {
        throw std::runtime_error(
            "Client ID mismatch in file response");
    }

    if (std::strncmp(
            response.fileName,
            fileName.c_str(),
            sizeof(response.fileName)) != 0)
    {
        throw std::runtime_error(
            "File name mismatch in file response");
    }

    if (response.contentSize != encryptedFileSize)
    {
        throw std::runtime_error(
            "File size mismatch in file response");
    }
}

ResponsePayload1603 ClientSession::receiveFileResponse()
{
    std::vector<uint8_t> headerBytes =
        networkClient_.receiveData(sizeof(ResponseHeader));

    ResponseHeader responseHeader =
        MessageCodec::parseResponseHeader(headerBytes);

    if (responseHeader.code == GENERAL_ERROR)
    {
        throw std::runtime_error(
            "Server returned general error (1607)");
    }

    if (responseHeader.code != FILE_RECEIVED_RESPONSE)
    {
        throw std::runtime_error(
            "Unexpected response code after sending file");
    }

    if (responseHeader.payloadSize != sizeof(ResponsePayload1603))
    {
        throw std::runtime_error(
            "Invalid file response payload size");
    }

    std::vector<uint8_t> payloadBytes =
        networkClient_.receiveData(responseHeader.payloadSize);

    return MessageCodec::parseFileResponse(payloadBytes);
}

void ClientSession::receiveCRCConfirmation()
{
    std::vector<uint8_t> headerBytes =
        networkClient_.receiveData(sizeof(ResponseHeader));

    ResponseHeader header =
        MessageCodec::parseResponseHeader(headerBytes);

    if (header.code == GENERAL_ERROR)
    {
        throw std::runtime_error("Server returned a general error");
    }

    if (header.code != MESSAGE_RECEIVED_RESPONSE)
    {
        throw std::runtime_error("Unexpected CRC confirmation response");
    }

    if (header.payloadSize != sizeof(ResponsePayloadClientId))
    {
        throw std::runtime_error("Invalid CRC confirmation payload size");
    }

    std::vector<uint8_t> payloadBytes =
        networkClient_.receiveData(header.payloadSize);

    ResponsePayloadClientId payload =
        MessageCodec::parseClientIdPayload(payloadBytes);

    if (std::memcmp(payload.clientId, clientId_.clientId, CLIENT_ID_SIZE) != 0)
    {
        throw std::runtime_error("Client ID mismatch in CRC confirmation");
    }
}
