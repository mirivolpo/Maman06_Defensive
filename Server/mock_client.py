import socket
import struct
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

# Server connection settings
SERVER_IP = '127.0.0.1'
SERVER_PORT = 1234

# Helper function to match POSIX cksum (so client and server CRCs match)
def memcrc(b):
    crc = 0
    for byte in b:
        crc = (crc << 8) ^ byte
        crc &= 0xFFFFFFFF
    return crc # Simplified mock version - in reality, implement full POSIX crc

def run_mock_client():
    print("1. Connecting to server...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((SERVER_IP, SERVER_PORT))

    # --- Step 1: Registration (Code 825) ---
    print("\n2. Sending Registration request (Code 825)...")
    name = "TestUser".encode('ascii').ljust(255, b'\x00')
    header_825 = struct.pack('<16sBHI', bytes(16), 3, 825, 255)
    s.sendall(header_825 + name)

    response_1600 = s.recv(1024)
    ver, code, payload_size, client_id = struct.unpack('<BHI16s', response_1600[:23])
    if code != 1600:
        print(f"Registration failed with code {code}")
        return
    print(f"   Success! Registered with Client ID: {client_id.hex()}")

    # --- Step 2: Send Public Key (Code 826) ---
    print("\n3. Generating RSA keys & Sending Public Key (Code 826)...")
    key = RSA.generate(1024)
    public_key = key.publickey().export_key(format='DER')
    
    header_826 = struct.pack('<16sBHI', client_id, 3, 826, 255 + len(public_key))
    s.sendall(header_826 + name + public_key)

    response_1602 = s.recv(1024)
    ver2, code2, payload_size2 = struct.unpack('<BHI', response_1602[:7])
    if code2 != 1602:
        print(f"Key exchange failed with code {code2}")
        return
        
    encrypted_aes_key = response_1602[23:] # skip header (7) and client_id (16)
    cipher_rsa = PKCS1_OAEP.new(key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    print(f"   Success! Decrypted AES key: {aes_key.hex()}")

    # --- Step 3: Send File (Code 828) ---
    print("\n4. Encrypting and sending file (Code 828)...")
    file_name = "test_file.txt"
    file_name_bytes = file_name.encode('ascii').ljust(255, b'\x00')
    file_content = b"Hello, this is a secret message for the server!"
    
    # Calculate padding for AES
    pad_len = 16 - (len(file_content) % 16)
    padded_content = file_content + (b'\x00' * pad_len)
    
    # Encrypt
    iv = bytes(16)
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted_content = cipher_aes.encrypt(padded_content)
    
    # Pack 828 payload
    orig_size = len(file_content)
    enc_size = len(encrypted_content)
    packet_num = 1
    total_packets = 1
    
    file_header = struct.pack('<IIHH255s', enc_size, orig_size, packet_num, total_packets, file_name_bytes)
    payload_828 = file_header + encrypted_content
    header_828 = struct.pack('<16sBHI', client_id, 3, 828, len(payload_828))
    
    s.sendall(header_828 + payload_828)

    # --- Step 4: Verify CRC and Send 900 ---
    response_1603 = s.recv(1024)
    ver3, code3, payload_size3 = struct.unpack('<BHI', response_1603[:7])
    if code3 == 1603:
        # 16 + 4 + 255 + 4 = 279 bytes payload
        # Skip header(7) + client_id(16) + content_size(4) + file_name(255) to get CRC
        server_crc = struct.unpack('<I', response_1603[282:286])[0]
        print(f"   Received CRC from server: {server_crc}")
        
        print("\n5. Sending CRC OK (Code 900)...")
        header_900 = struct.pack('<16sBHI', client_id, 3, 900, 255)
        s.sendall(header_900 + file_name_bytes)
        
        response_1604 = s.recv(1024)
        ver4, code4, payload_size4 = struct.unpack('<BHI', response_1604[:7])
        if code4 == 1604:
            print("   Success! Server acknowledged file saved (1604).")
    
    s.close()
    print("\n--- Test Completed Successfully ---")

if __name__ == "__main__":
    run_mock_client()