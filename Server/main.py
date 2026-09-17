"""
Maman 06 server entry point.
"""
from server import Server


def main():
    """
    Main function to initialize and start the server.
    """
    # Create a new server instance
    my_server = Server()

    # Start the server loop
    my_server.start()

if __name__ == "__main__":
    main()
