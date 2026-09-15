"""
Server module for Defensive Systems Programming project.
Handles starting the server and loading the configuration.
"""

import os
import socket
import struct
from datetime import datetime
import uuid
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


DEFAULT_PORT = 1369
HOST = '127.0.0.1'  # Localhost - the server runs on your local machine
HEADER_FORMAT = '<16sBHI'
HEADER_SIZE = 23

# This dictionary will serve as our RAM database for clients.
# Key: client_id (bytes), Value: Client object
clients = {}


class Client:
    """
    Represents a connected client and stores their data in RAM.
    """
    def __init__(self, client_id, name):
        self.client_id = client_id
        self.name = name
        self.public_key = None
        self.aes_key = None
        self.last_seen = datetime.now()


def get_port():
    """
    Read the port number from port.info.
    Returns the default port if the file is missing or contains invalid data.
    """
    if not os.path.exists("port.info"):
        print(f"Warning: port.info not found. Using default port {DEFAULT_PORT}")
        return DEFAULT_PORT

    try:
        with open("port.info", "r", encoding="utf-8") as f:
            port_str = f.read().strip()
            return int(port_str)
    except (OSError, ValueError):
        print(f"Warning: Error reading port.info. Using default port {DEFAULT_PORT}")
        return DEFAULT_PORT


def parse_header(conn):
    """
    Reads 23 bytes from the connection and unpacks the header.
    Returns a tuple: (client_id, version, code, payload_size) or None if fails.
    """
    try:
        # Read exactly the header size
        header_data = conn.recv(HEADER_SIZE)
        
        # If the client disconnected or didn't send enough data
        if not header_data or len(header_data) < HEADER_SIZE:
            return None
            
        # Unpack the binary data based on the little-endian format
        client_id, version, code, payload_size = struct.unpack(HEADER_FORMAT, header_data)
        return client_id, version, code, payload_size
        
    except (OSError, struct.error):
        return None
def handle_registration(conn, payload_size):
    """
    Handles code 825 (Registration).
    Reads the name, generates a UUID, saves to RAM, and sends response.
    """
    try:
        # Read the payload which contains the name
        payload = conn.recv(payload_size)
        
        # Decode ASCII and remove null terminators
        name = payload.decode('ascii').rstrip('\x00')
        
        # Check if the name already exists in our RAM database
        for existing_client in clients.values():
            if existing_client.name == name:
                print(f"Registration failed: Name '{name}' already exists.")
                # Send 1601 Failure response: Version(3), Code(1601), PayloadSize(0)
                response_header = struct.pack('<BHI', 3, 1601, 0)
                conn.sendall(response_header)
                return
        
        # Name is valid, generate a new UUID (16 bytes)
        new_client_id = uuid.uuid4().bytes
        
        # Save to our clients dictionary
        clients[new_client_id] = Client(new_client_id, name)
        print(f"Registered new client: '{name}' with ID: {new_client_id.hex()}")
        
        # Send 1600 Success response: Version(3), Code(1600), PayloadSize(16 bytes UUID)
        response_header = struct.pack('<BHI', 3, 1600, 16)
        # Send header + the UUID itself
        conn.sendall(response_header + new_client_id)
        
    except (OSError, UnicodeDecodeError, struct.error) as e:
        print(f"Error handling registration: {e}")

def handle_public_key_and_aes(conn, client_id, payload_size):
    """
    Handles code 826 (Send Public Key).
    Reads the client's name and public key, and updates the RAM database.
    """
    try:
        # Read the payload based on the size provided in the header
        payload = conn.recv(payload_size)
        
        # The payload structure for 826 is:
        # 255 bytes (Name) + 160 bytes (Public Key) = 415 bytes total
        if len(payload) < 415:
            print("Error: Payload too small for public key request.")
            return

        # Extract the name and public key
        # The name is the first 255 bytes, the key is the remaining 160 bytes
        name_bytes = payload[:255]
        public_key = payload[255:]
        
        # Decode the name (removing null terminators)
        name = name_bytes.decode('ascii').rstrip('\x00')
        
       # Verify the client exists in our RAM database
        if client_id not in clients:
            print(f"Error: Client {client_id.hex()} not found in RAM.")
            # According to protocol, if client not found we reject (1606) and return Client ID
            response_header = struct.pack('<BHI', 3, 1606, 16)
            conn.sendall(response_header + client_id)
            return
            
        # Update the client's public key in RAM
        clients[client_id].public_key = public_key
        print(f"Successfully received and stored public key for client '{name}'")
        
        # Generate a 256-bit (32 bytes) AES key
        aes_key = os.urandom(32)
        clients[client_id].aes_key = aes_key
        
        # Import the public key and encrypt the AES key
        rsa_key = RSA.import_key(public_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        
        # Prepare the 1602 response
        payload_size_1602 = 16 + len(encrypted_aes_key)
        response_header_1602 = struct.pack('<BHI', 3, 1602, payload_size_1602)
        
        # Send header + client_id + encrypted AES key
        conn.sendall(response_header_1602 + client_id + encrypted_aes_key)
        print(f"Generated and sent encrypted AES key to client '{name}'")
        
    except (OSError, UnicodeDecodeError, struct.error) as e:
        print(f"Error handling public key: {e}")

def start_server(port):
    """
    Starts the TCP server on the given port and waits for clients.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, port))
        server_socket.listen()
        print(f"Server is listening on {HOST}:{port}...")

        while True:
            # We use try-except here so if you press Ctrl+C it exits gracefully
            try:
                conn, addr = server_socket.accept()
                with conn:
                    print(f"Connected by client at {addr}")
                    header = parse_header(conn)
                    if header:
                        client_id, version, code, payload_size = header
                        print(f"Received Request - Code: {code}, Payload Size: {payload_size} bytes")
                        
                        if code == 825:
                            handle_registration(conn, payload_size)
                        elif code == 826:
                            handle_public_key_and_aes(conn, client_id, payload_size)    
                        else:
                            print(f"Code {code} is not supported yet.")
                    else:
                        print("Failed to read header or client disconnected.")
            except KeyboardInterrupt:
                print("\nServer manually stopped.")
                break


def main():
    """
    Main entry point for the server application.
    """
    port = get_port()
    start_server(port)


if __name__ == "__main__":
    main()
