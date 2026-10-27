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

    def save_file(self, file_name, content, client_id=None):
        """
        Saves the given binary content to a file in the upload directory.
        Returns True if successful, False otherwise.
        """

        # Strip directory components, including those using Windows separators.
        safe_file_name = os.path.basename(file_name.replace("\\", "/"))
        if safe_file_name in ("", ".", "..") or "\x00" in safe_file_name:
            print(f"Invalid file name: '{file_name}'")
            return False
        client_dir = constants.UPLOAD_DIR

        # Keep each client's files separate to avoid name collisions.
        if client_id is not None:
            client_dir = os.path.join(constants.UPLOAD_DIR, client_id.hex())
        os.makedirs(client_dir, exist_ok=True)
        file_path = os.path.join(client_dir, safe_file_name)
        try:
            with open(file_path, "wb") as f:
                f.write(content)
            print(f"Success! File '{file_name}' saved to {constants.UPLOAD_DIR}.")
            return True
        except OSError as e:
            print(f"Failure! Could not save file '{file_name}': {e}")
            return False
