import socket
import struct
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

HOST = '127.0.0.1'
PORT = 1234 # ודאי שזה תואם למספר בקובץ port.info שלך

def send_request(header, payload):
    """
    פונקציית עזר שפותחת חיבור, שולחת את הבקשה ומחזירה את התשובה מהשרת
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(header + payload)
        
        # קוראים את 7 הבתים של כותרת התשובה
        res_header = s.recv(7)
        if not res_header:
            return None, None
            
        version, code, payload_size = struct.unpack('<BHI', res_header)
        
        # קוראים את התוכן של התשובה בהתאם לגודל
        res_payload = s.recv(payload_size) if payload_size > 0 else b""
        return code, res_payload

def run_mock_client():
    # --- שלב 1: בקשת רישום (קוד 825) ---
    print("1. Sending Registration request (825)...")
    dummy_client_id = bytes(16) # מזהה ריק לבקשה הראשונה
    name = b"TestUser".ljust(255, b'\x00') # שם שמותאם בדיוק ל-255 בתים
    
    header_825 = struct.pack('<16sBHI', dummy_client_id, 3, 825, 255)
    code1, payload1 = send_request(header_825, name)
    
    if code1 == 1600:
        client_id = payload1 # שומרים את מזהה הלקוח האמיתי שקיבלנו מהשרת
        print(f"   Success! Server gave us ID: {client_id.hex()}")
    else:
        print("   Registration failed.")
        return

    # --- שלב 2: שליחת מפתח ציבורי (קוד 826) ---
    print("\n2. Generating RSA 1024-bit keys...")
    key = RSA.generate(1024)
    pub_key = key.publickey().export_key(format='DER')
    
    print("   Sending Public Key request (826)...")
    payload_826 = name + pub_key
    header_826 = struct.pack('<16sBHI', client_id, 3, 826, len(payload_826))
    
    code2, payload2 = send_request(header_826, payload_826)
    
    if code2 == 1602:
        server_client_id = payload2[:16]
        encrypted_aes_key = payload2[16:]
        print("   Success! Received encrypted AES key from server.")
        
        # --- שלב 3: הפענוח! ---
        print("\n3. Decrypting the AES key...")
        cipher_rsa = PKCS1_OAEP.new(key)
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)
        print(f"   TA-DA! The secret AES key is: {aes_key.hex()}")

if __name__ == "__main__":
    run_mock_client()