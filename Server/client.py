"""
Client module 
"""

class Client:
    """
    Represents a client and stores their data in RAM.
    """
    def __init__(self, client_id, name):
        self.client_id = client_id
        self.name = name
        self.public_key = None
        self.aes_key = None
        self.temp_file_content = None
        self.temp_file_name = None
