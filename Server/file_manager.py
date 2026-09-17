"""
File Manager module
"""
import os

import constants


class FileManager:
    """Handles reading and writing files to the local disk."""

    def __init__(self):
        """Initializes the manager and ensures the upload directory exists."""
        os.makedirs(constants.UPLOAD_DIR, exist_ok=True)

    def save_file(self, file_name, content):
        """
        Saves the given binary content to a file in the upload directory.
        Returns True if successful, False otherwise.
        """
        file_path = os.path.join(constants.UPLOAD_DIR, file_name)
        try:
            with open(file_path, 'wb') as f:
                f.write(content)
            print(f"Success! File '{file_name}' saved to {constants.UPLOAD_DIR}.")
            return True
        except OSError as e:
            print(f"Failure! Could not save file '{file_name}': {e}")
            return False
