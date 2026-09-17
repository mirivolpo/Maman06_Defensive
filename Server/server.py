"""
Server module for the Defensive Systems Programming Server.
Manages the main socket, threading, and global state.
"""
import os
import socket
import threading

import constants
from file_manager import FileManager
from request_handler import RequestHandler


class Server:
    """Main server class that listens for clients and spawns threads."""

    def __init__(self):
        """Initializes the server state and loads the port configuration."""
        self.clients = {}
        self.file_manager = FileManager()
        self.port = self._read_port()

    def _read_port(self):
        """
        Reads the port from the configuration file.
        Returns the default port if the file is missing or invalid.
        """
        try:
            if os.path.exists(constants.PORT_INFO_FILE):
                with open(constants.PORT_INFO_FILE, 'r', encoding='utf-8') as f:
                    return int(f.read().strip())
        except (ValueError, OSError) as e:
            print(f"Warning: Could not read port from file. Using default 1369. Error: {e}")

        # Default port 1369 as required if reading fails
        return constants.DEFAULT_PORT

    def start(self):
        """Starts the server, listens for connections, and handles them via threads."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((constants.HOST, self.port))
            server_socket.listen()
            print(f"Server started. Listening on port {self.port}...")

            while True:
                try:
                    conn, addr = server_socket.accept()

                    # Create a handler instance for the new client
                    handler = RequestHandler(self.clients, self.file_manager)

                    # Spawn a new thread for the client
                    client_thread = threading.Thread(
                        target=handler.handle_client_request,
                        args=(conn, addr)
                    )
                    client_thread.start()

                except OSError as e:
                    print(f"Server socket error: {e}")
                    break
