"""
Server module for Defensive Systems Programming project.
Handles starting the server and loading the configuration.
"""

import os
import socket
import threading
import struct
from datetime import datetime
import uuid
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from cksum import memcrc
from constants import *



os.makedirs(UPLOAD_DIR, exist_ok=True)

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
        self.temp_file_content = None
        self.temp_file_name = None
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
        header_data = conn.recv(REQ_HEADER_SIZE)
        
        # If the client disconnected or didn't send enough data
        if not header_data or len(header_data) < REQ_HEADER_SIZE:
            return None
            
        # Unpack the binary data based on the little-endian format
        client_id, version, code, payload_size = struct.unpack(REQ_HEADER_FORMAT, header_data)
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
                # Send 1601 Failure response
                response_header = struct.pack(RESPONSE_HEADER_FORMAT, SERVER_VERSION, RES_REGISTER_FAIL, EMPTY_PAYLOAD_SIZE)
                conn.sendall(response_header)
                return
        
        # Name is valid, generate a new UUID (16 bytes)
        new_client_id = uuid.uuid4().bytes
        
        # Save to our clients dictionary
        clients[new_client_id] = Client(new_client_id, name)
        print(f"Registered new client: '{name}' with ID: {new_client_id.hex()}")
        
        # Send 1600 Success response
        response_header = struct.pack(RESPONSE_HEADER_FORMAT, SERVER_VERSION, RES_REGISTER_SUCC, UUID_SIZE)
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
        
       
        if len(payload) < REQ_SEND_PUB_KEY_PAYLOAD:
            print("Error: Payload too small for public key request.")
            return

        # Extract the name and public key
        # The name is the first 255 bytes, the key is the remaining 160 bytes
        name_bytes = payload[:CLIENT_NAME_SIZE]
        public_key = payload[CLIENT_NAME_SIZE:]
        
        # Decode the name (removing null terminators)
        name = name_bytes.decode('ascii').rstrip('\x00')
        
       # Verify the client exists in our RAM database
        if client_id not in clients:
            print(f"Error: Client {client_id.hex()} not found in RAM.")
            # General server error (1607) since this is an unexpected state
            response_header = struct.pack(RESPONSE_HEADER_FORMAT, SERVER_VERSION, RES_GENERAL_ERROR, EMPTY_PAYLOAD_SIZE)
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

def handle_reconnect(conn, client_id, payload_size):
    """
    Handles code 827 (Reconnect).
    Checks if client exists and has a public key.
    Sends 1605 (Success) or 1606 (Failure).
    """
    try:
        # Read the payload which contains only the name (255 bytes)
        payload = conn.recv(payload_size)
        name = payload.decode('ascii').rstrip('\x00')
        
        # Check if client exists in RAM and has a public key
        if client_id not in clients or clients[client_id].public_key is None:
            print(f"Reconnect rejected for '{name}'. Client or public key not found.")
            # Send 1606 Reconnect Rejected (Header + 16 bytes Client ID)
            response_header = struct.pack('<BHI', 3, 1606, 16)
            conn.sendall(response_header + client_id)
            return
            
        print(f"Reconnect accepted for client '{name}'. Generating new AES key...")
        
        # Client exists! Generate a NEW AES key
        aes_key = os.urandom(32)
        clients[client_id].aes_key = aes_key
        
        # Encrypt the new AES key with the client's EXISTING public key
        rsa_key = RSA.import_key(clients[client_id].public_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        
        # Send 1605 Reconnect Accepted (Same structure as 1602)
        payload_size_1605 = 16 + len(encrypted_aes_key)
        response_header_1605 = struct.pack('<BHI', 3, 1605, payload_size_1605)
        conn.sendall(response_header_1605 + client_id + encrypted_aes_key)
        print(f"Successfully reconnected and sent new encrypted AES key to '{name}'")
        
    except (OSError, UnicodeDecodeError, struct.error, ValueError) as e:
        print(f"Error handling reconnect: {e}")

def handle_send_file(conn, client_id, payload_size):
    """Parses the request header and reads the encrypted file payload in chunks from the client connection."""
    try:
        # Check if the client exists in RAM and has an AES key
        if client_id not in clients or clients[client_id].aes_key is None:
            print("Error: Client not found or missing AES key. Cannot receive file.")
            return

        # Calculate the size of the fixed part of the payload: 4 + 4 + 2 + 2 + 255 = 267 bytes
        file_header_size = 267
        file_header = conn.recv(file_header_size)
        
        # 'I' = 4 bytes (unsigned int), 'H' = 2 bytes (unsigned short), '255s' = 255 bytes string
        content_size, orig_file_size, packet_num, total_packets, file_name_bytes = struct.unpack('<IIHH255s', file_header)
        
        # Clean the file name from null terminators
        file_name = file_name_bytes.decode('ascii').rstrip('\x00')
        print(f"Receiving file '{file_name}' (Encrypted size: {content_size} bytes)...")
        
        # Read the encrypted content from the socket in chunks to handle large files
        encrypted_content = b""
        bytes_left = content_size
        while bytes_left > 0:
            chunk = conn.recv(min(4096, bytes_left))
            if not chunk:
                break
            encrypted_content += chunk
            bytes_left -= len(chunk)
            
        print(f"Successfully received {len(encrypted_content)} bytes of encrypted data.")
        
        # Create an initialization vector (IV) of 16 bytes filled with zeros
        iv = bytes(16)
        
        # Initialize the AES cipher in CBC mode with the client's key and the zeroed IV
        cipher_aes = AES.new(clients[client_id].aes_key, AES.MODE_CBC, iv)
        
        # Decrypt the content
        decrypted_content_padded = cipher_aes.decrypt(encrypted_content)
        
        # Block ciphers like AES add padding to the end of the file. 
        # We use the original file size from the header to slice exactly the real data
        decrypted_content = decrypted_content_padded[:orig_file_size]
        
        print("Decryption successful. Calculating CRC...")
        
        # Calculate the CRC checksum on the decrypted data
        checksum = memcrc(decrypted_content)
        
        print(f"Calculated CRC: {checksum}")

        # Pack the payload for response 1603 
        # '16s' = Client ID, 'I' = Content Size, '255s' = File Name, 'I' = Checksum
        payload_1603 = struct.pack('<16sI255sI', client_id, content_size, file_name_bytes, checksum)
        
        # Pack the header: Version 3, Code 1603, and the payload size
        header_1603 = struct.pack('<BHI', 3, 1603, len(payload_1603))
        
        # Send the complete response back to the client
        conn.sendall(header_1603 + payload_1603)
        print("Response 1603 sent to client with CRC verification.")
        
        # We also need to save the decrypted content temporarily in RAM so we can write it
        # to disk later IF the client confirms the CRC is valid (code 900)
        clients[client_id].temp_file_content = decrypted_content
        clients[client_id].temp_file_name = file_name  

    except (OSError, UnicodeDecodeError, struct.error, ValueError) as e:
        print(f"Error handling file upload: {e}")        

def handle_crc_responses(conn, client_id, code, payload_size):
    """Handles CRC status codes 900 (valid), 901 (invalid retry), and 902 (invalid abort)."""
    try:
        # Read the 255-byte file name payload
        file_name_bytes = conn.recv(payload_size)
        file_name = file_name_bytes.decode('ascii').rstrip('\x00')
        
        if code == 900:
            # Construct the full path and save the file to the local directory
            file_path = os.path.join(UPLOAD_DIR, file_name)
            with open(file_path, 'wb') as f:
                f.write(clients[client_id].temp_file_content)
            print(f"Success! File '{file_name}' saved to {UPLOAD_DIR}.")
            
            # Send 1604 Message received
            response_header = struct.pack('<BHI', 3, 1604, 16)
            conn.sendall(response_header + client_id)
            
        elif code == 901:
            print(f"Client reported invalid CRC for '{file_name}'. Waiting for re-send...")
            
        elif code == 902:
            print(f"Client aborted transfer for '{file_name}' after 4 invalid CRCs.")
            
            # Send 1604 Message received (Abort acknowledgment)
            response_header = struct.pack('<BHI', 3, 1604, 16)
            conn.sendall(response_header + client_id)
            
        # Clear the temporary RAM memory for this client
        clients[client_id].temp_file_content = None
        clients[client_id].temp_file_name = None
    except OSError as e:
        print(f"File system error (e.g. out of disk space) handling CRC response: {e}")
        # Send 1607 General Error if saving to disk failed
        response_header = struct.pack('<BHI', 3, 1607, 0)
        conn.sendall(response_header)
        
    except (UnicodeDecodeError, struct.error, ValueError) as e:
        print(f"Error handling CRC response: {e}")

def handle_client(conn, addr):
    """
    Handles continuous communication with a single connected client.
    Keeps reading requests until the client disconnects.
    """
    print(f"Connected by client at {addr}")
    
    # Start a continuous loop for this specific client
    while True:
        try:
            header = parse_header(conn)
            if not header:
                print(f"Client {addr} disconnected.")
                break # Exit the loop if client disconnected properly
                
            client_id, version, code, payload_size = header
            print(f"Received Request - Code: {code}, Payload Size: {payload_size} bytes")
            
            # Route the request based on the code
            if code == 825:
                handle_registration(conn, payload_size)
            elif code == 826:
                handle_public_key_and_aes(conn, client_id, payload_size)
            elif code == 827:
                handle_reconnect(conn, client_id, payload_size)
            elif code == 828:
                handle_send_file(conn, client_id, payload_size)
            elif code in (900, 901, 902):
                handle_crc_responses(conn, client_id, code, payload_size)
            else:
                print(f"Code {code} is not supported yet.")
                
        except ConnectionResetError:
            print(f"Client at {addr} closed the connection unexpectedly.")
            break
        except Exception as e:
            print(f"Error handling client {addr}: {e}")
            break
            
    # Close the connection only when the loop breaks (client left)
    conn.close()
  
def start_server(port):
    """Starts the TCP server and waits for clients using threads for concurrency."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, port))
        server_socket.listen()
        print(f"Server is listening on {HOST}:{port}...")

        # Infinite loop to accept incoming client connections
        while True:
            try:
                conn, addr = server_socket.accept()
                
                # Create and start a new thread for each client
                client_thread = threading.Thread(target=handle_client, args=(conn, addr))
                client_thread.start()
                
            except KeyboardInterrupt:
                print("\nServer manually stopped.")
                break
            except Exception as e:
                print(f"Error accepting client: {e}")

def main():
    """
    Main entry point for the server application.
    """
    port = get_port()
    start_server(port)


if __name__ == "__main__":
    main()
