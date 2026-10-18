"""
Request Handler module
Handles the parsing and routing of protocol requests.
"""
import os
import struct
import uuid

import constants
from cksum import memcrc
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

from client import Client


def recv_exact(conn, size):
    """Receive exactly size bytes from the socket."""
    data = bytearray()

    while len(data) < size:
        chunk = conn.recv(size - len(data))

        if not chunk:
            raise ConnectionError("Client disconnected during data reception.")

        data.extend(chunk)

    return bytes(data)



class RequestHandler:
    """Handles client requests and executes the appropriate protocol actions."""

    def __init__(self, clients_db, file_manager, files_db=None):
        self.clients = clients_db
        self.file_manager = file_manager
        self.files = files_db

    def parse_header(self, conn):
        """
        Reads the request header from the client connection.
        Unpacks the binary data into client_id, version, code, and payload_size.
        Returns a tuple of these values, or None if the connection fails.
        """
        try:
            header_data = recv_exact(conn, constants.REQ_HEADER_SIZE)
            if not header_data or len(header_data) < constants.REQ_HEADER_SIZE:
                return None

            # Unpack the little-endian formatted header
            client_id, version, code, payload_size = struct.unpack(
                constants.REQ_HEADER_FORMAT,
                header_data)

            return client_id, version, code, payload_size

        except (OSError, struct.error):
            return None

    def handle_client_request(self, conn, addr):
        """
        Manages the continuous session with a connected client.
        Reads incoming requests and routes them to the appropriate handler.
        """
        print(f"Connected by client at {addr}")

        while True:
            try:
                # Parse the incoming request header
                header = self.parse_header(conn)
                if not header:
                    print(f"Client {addr} disconnected.")
                    break

                client_id, _version, code, payload_size = header
                print(f"Received Request - Code: {code}, Payload Size: {payload_size} bytes")

                # Route the request based on the protocol code
                if code == constants.REQ_REGISTER:
                    self.handle_registration(conn, payload_size)

                elif code == constants.REQ_SEND_PUB_KEY:
                    self.handle_public_key_and_aes(conn, client_id, payload_size)

                elif code == constants.REQ_RECONNECT:
                    self.handle_reconnect(conn, client_id, payload_size)

                elif code == constants.REQ_SEND_FILE:
                    self.handle_send_file(conn, client_id, payload_size)

                elif code in (
                    constants.REQ_CRC_OK,
                    constants.REQ_CRC_INVALID_RETRY,
                    constants.REQ_CRC_INVALID_ABORT):
                    self.handle_crc_responses(conn, client_id, code, payload_size)

                else:
                    print(f"Code {code} is not supported yet.")

            except ConnectionResetError:
                print(f"Client at {addr} closed the connection unexpectedly.")
                break
            except (ConnectionError, OSError, struct.error, ValueError) as e:
                print(f"Error handling client {addr}: {e}")
                break

        # Ensure the connection is properly closed when the session ends
        conn.close()

    def handle_registration(self, conn, payload_size):
        """
        Handles protocol request 825 (Registration).
        Reads the client's name, generates a unique UUID,
        saves it to RAM, and sends the appropriate response.
        """
        try:
            payload = recv_exact(conn, payload_size)
            name = payload.decode('ascii').rstrip('\x00')

            # Check if the name already exists in the RAM database
            for existing_client in self.clients.values():
                if existing_client.name == name:
                    print(f"Registration failed: Name '{name}' already exists.")

                    response_header = struct.pack(
                        constants.RESPONSE_HEADER_FORMAT,
                        constants.SERVER_VERSION,
                        constants.RES_REGISTER_FAIL,
                        constants.EMPTY_PAYLOAD_SIZE)
                    conn.sendall(response_header)
                    return

            # Name is valid, generate a new UUID (16 bytes)
            new_client_id = uuid.uuid4().bytes

            # Save to the shared clients dictionary
            self.clients[new_client_id] = Client(new_client_id, name)
            print(f"Registered new client: '{name}' with ID: {new_client_id.hex()}")

            # Send 1600 Success response with the new UUID
            response_header = struct.pack(
                constants.RESPONSE_HEADER_FORMAT,
                constants.SERVER_VERSION,
                constants.RES_REGISTER_SUCC,
                constants.UUID_SIZE)

            conn.sendall(response_header + new_client_id)

        except (OSError, UnicodeDecodeError, struct.error) as e:
            print(f"Error handling registration: {e}")

    def handle_public_key_and_aes(self, conn, client_id, payload_size):
        """
        Handles protocol request 826 (Send Public Key).
        Reads the public key, generates an AES key, encrypts it with RSA,
        and sends it back to the client.
        """
        try:
            payload = recv_exact(conn, payload_size)

            if len(payload) < constants.PUB_KEY_PAYLOAD_SIZE:
                print("Error: Payload too small for public key request.")
                return

            name_bytes = payload[:constants.CLIENT_NAME_SIZE]
            public_key = payload[constants.CLIENT_NAME_SIZE:]
            name = name_bytes.decode('ascii').rstrip('\x00')

            if client_id not in self.clients:
                print(f"Error: Client {client_id.hex()} not found in RAM.")
                response_header = struct.pack(
                    constants.RESPONSE_HEADER_FORMAT,
                    constants.SERVER_VERSION,
                    constants.RES_GENERAL_ERROR,
                    constants.EMPTY_PAYLOAD_SIZE)
                conn.sendall(response_header)
                return

            self.clients[client_id].public_key = public_key
            print(f"Successfully received public key for client '{name}'")


            aes_key = os.urandom(constants.AES_KEY_SIZE_BYTES)
            self.clients[client_id].aes_key = aes_key

            # Encrypt the AES key with the client's public RSA key
            rsa_key = RSA.import_key(public_key)
            cipher_rsa = PKCS1_OAEP.new(rsa_key)
            encrypted_aes_key = cipher_rsa.encrypt(aes_key)

            payload_size_1602 = constants.UUID_SIZE + len(encrypted_aes_key)
            response_header_1602 = struct.pack(
                constants.RESPONSE_HEADER_FORMAT,
                constants.SERVER_VERSION,
                constants.RES_PUB_KEY_AES,
                payload_size_1602)

            conn.sendall(response_header_1602 + client_id + encrypted_aes_key)
            print(f"Sent encrypted AES key to client '{name}'")

        except (OSError, UnicodeDecodeError, struct.error, ValueError) as e:
            print(f"Error handling public key: {e}")

    def handle_reconnect(self, conn, client_id, payload_size):
        """
        Handles protocol request 827 (Reconnect).
        Checks if client exists and has a valid RSA public key.
        Sends response 1605 (Success with new AES) or 1606 (Failure).
        """
        try:
            payload = recv_exact(conn, payload_size)
            name = payload.decode('ascii').rstrip('\x00')

            # Reject if client or public key is missing
            if client_id not in self.clients or self.clients[client_id].public_key is None:
                print(f"Reconnect rejected for '{name}'.")

                response_header = struct.pack(
                    constants.RESPONSE_HEADER_FORMAT,
                    constants.SERVER_VERSION,
                    constants.RES_RECONNECT_FAIL,
                    constants.UUID_SIZE)
                conn.sendall(response_header + client_id)
                return

            print(f"Reconnect accepted for client '{name}'. Generating new AES key...")

            aes_key = os.urandom(constants.AES_KEY_SIZE_BYTES)
            self.clients[client_id].aes_key = aes_key

            rsa_key = RSA.import_key(self.clients[client_id].public_key)
            cipher_rsa = PKCS1_OAEP.new(rsa_key)
            encrypted_aes_key = cipher_rsa.encrypt(aes_key)

            payload_size_1605 = constants.UUID_SIZE + len(encrypted_aes_key)
            response_header_1605 = struct.pack(
                constants.RESPONSE_HEADER_FORMAT,
                constants.SERVER_VERSION,
                constants.RES_RECONNECT_SUCC,
                payload_size_1605)

            conn.sendall(response_header_1605 + client_id + encrypted_aes_key)
            print(f"Sent new encrypted AES key to '{name}'")

        except (OSError, UnicodeDecodeError, struct.error, ValueError) as e:
            print(f"Error handling reconnect: {e}")

    def handle_send_file(self, conn, client_id, _payload_size):
        """
        Handles protocol request 828 (Send File).
        Reads the encrypted file, decrypts it using AES, calculates the CRC checksum,
        and sends response 1603.
        """
        try:
            if client_id not in self.clients or self.clients[client_id].aes_key is None:
                print("Error: Client not found or missing AES key.")
                # Send 1607 General Error response
                response_header = struct.pack(
                    constants.RESPONSE_HEADER_FORMAT,
                    constants.SERVER_VERSION,
                    constants.RES_GENERAL_ERROR,
                    constants.EMPTY_PAYLOAD_SIZE)
                conn.sendall(response_header)
                return

            file_header_size = constants.FILE_PAYLOAD_HEADER_SIZE
            file_header = recv_exact(conn, file_header_size)

            (
                content_size,
                orig_file_size,
                _packet_num,
                _total_packets,
                file_name_bytes
            ) = struct.unpack(
                constants.PAYLOAD_FORMAT_828_HEADER,
                file_header
            )


            file_name = file_name_bytes.decode('ascii').rstrip('\x00')
            print(f"Receiving file '{file_name}'...")

            encrypted_content = recv_exact(conn, content_size)

            # Initialize AES cipher in CBC mode with zeroed IV
            iv = bytes(constants.AES_IV_SIZE_BYTES)
            cipher_aes = AES.new(self.clients[client_id].aes_key, AES.MODE_CBC, iv)

            decrypted_content_padded = cipher_aes.decrypt(encrypted_content)
            decrypted_content = decrypted_content_padded[:orig_file_size]

            checksum = memcrc(decrypted_content)

            payload_1603 = struct.pack(
                constants.PAYLOAD_FORMAT_1603,
                client_id,
                content_size,
                file_name_bytes,
                checksum)

            header_1603 = struct.pack(
                constants.RESPONSE_HEADER_FORMAT,
                constants.SERVER_VERSION,
                constants.RES_FILE_OK_CRC,
                len(payload_1603))

            conn.sendall(header_1603 + payload_1603)

            self.clients[client_id].temp_file_content = decrypted_content
            self.clients[client_id].temp_file_name = file_name

        except (OSError, UnicodeDecodeError, struct.error, ValueError) as e:
            print(f"Error handling file upload: {e}")

    def handle_crc_responses(self, conn, client_id, code, payload_size):
        """
        Handles CRC status codes 900 (Valid), 901 (Invalid retry), and 902 (Invalid abort).
        Saves the file using FileManager if valid.
        """
        try:
            file_name_bytes = recv_exact(conn, payload_size)
            file_name = file_name_bytes.decode('ascii').rstrip('\x00')

            if code == constants.REQ_CRC_OK:
                is_saved = self.file_manager.save_file(
                    file_name,
                    self.clients[client_id].temp_file_content
                )

                if is_saved:
                    self.files[(client_id, file_name)] = True
                    response_header = struct.pack(
                        constants.RESPONSE_HEADER_FORMAT,
                        constants.SERVER_VERSION,
                        constants.RES_MSG_RECEIVED,
                        constants.UUID_SIZE)
                    conn.sendall(response_header + client_id)
                else:
                    response_header = struct.pack(
                        constants.RESPONSE_HEADER_FORMAT,
                        constants.SERVER_VERSION,
                        constants.RES_GENERAL_ERROR,
                        constants.EMPTY_PAYLOAD_SIZE)
                    conn.sendall(response_header)

            elif code == constants.REQ_CRC_INVALID_RETRY:
                print(f"Client reported invalid CRC for '{file_name}'. Waiting for re-send...")

            elif code == constants.REQ_CRC_INVALID_ABORT:
                print(f"Client aborted transfer for '{file_name}'.")
                response_header = struct.pack(
                    constants.RESPONSE_HEADER_FORMAT,
                    constants.SERVER_VERSION,
                    constants.RES_MSG_RECEIVED,
                    constants.UUID_SIZE)
                conn.sendall(response_header + client_id)

            self.clients[client_id].temp_file_content = None
            self.clients[client_id].temp_file_name = None

        except (OSError, UnicodeDecodeError, struct.error, ValueError) as e:
            print(f"Error handling CRC response: {e}")
