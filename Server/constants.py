"""Constants module"""


#Server & Network Configuration
HOST = '127.0.0.1'         # Localhost
DEFAULT_PORT = 1369
UPLOAD_DIR = 'uploads'     # Local directory for saving client files
NETWORK_CHUNK_SIZE = 4096  # Buffer size for reading data streams
PORT_INFO_FILE = 'port.info'

#Protocol Settings
SERVER_VERSION = 3
UUID_SIZE = 16
CLIENT_NAME_SIZE = 255     # Max size for client name string (null-terminated)
EMPTY_PAYLOAD_SIZE = 0     # Used when a response has no payload content

#Cryptography Constants
AES_KEY_SIZE_BYTES = 32    # 256-bit AES key size
AES_IV_SIZE_BYTES = 16     # 16-byte zeroed IV for AES-CBC mode
RSA_PUBLIC_KEY_SIZE = 160  # Expected size of the RSA public key in bytes

#Payload Fixed Sizes
REQ_HEADER_SIZE = 23
FILE_PAYLOAD_HEADER_SIZE = 267  # 4(size) + 4(orig_size) + 2(packet) + 2(total) + 255(name)
PUB_KEY_PAYLOAD_SIZE = 415      # 255(name) + 160(public key)

#Request Codes (Client -> Server)
REQ_REGISTER = 825
REQ_SEND_PUB_KEY = 826
REQ_RECONNECT = 827
REQ_SEND_FILE = 828
REQ_CRC_OK = 900
REQ_CRC_INVALID_RETRY = 901
REQ_CRC_INVALID_ABORT = 902

#Response Codes (Server -> Client)
RES_REGISTER_SUCC = 1600
RES_REGISTER_FAIL = 1601
RES_PUB_KEY_AES = 1602
RES_FILE_OK_CRC = 1603
RES_MSG_RECEIVED = 1604
RES_RECONNECT_SUCC = 1605
RES_RECONNECT_FAIL = 1606
RES_GENERAL_ERROR = 1607

#Struct Formats
REQ_HEADER_FORMAT = '<16sBHI'
RESPONSE_HEADER_FORMAT = '<BHI'
PAYLOAD_FORMAT_1603 = '<16sI255sI'
PAYLOAD_FORMAT_828_HEADER = '<IIHH255s'
