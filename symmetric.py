import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64


class SymmetricEncryption:
    """
    A class for symmetric encryption operations using AES.
    Supports AES-CTR, AES-CBC and AES-GCM modes with proper padding and secure key handling.
    """

    def __init__(self, key=None, mode="CTR"):
        """
        Initialize the symmetric encryption object with a key and mode.

        Args:
            key (bytes, optional): Encryption key. If not provided, a new key will be generated.
            mode (str, optional): Encryption mode, "CTR", "CBC", or "GCM". Defaults to "CTR" for speed.
        """
        self.backend = default_backend()
        self.mode = mode.upper()

        if key:
            self.key = key
        else:
            # Generate a secure random 128-bit key
            self.key = os.urandom(16)  # 16 bytes = 128 bits (AES-128 is faster than AES-256)

    def encrypt(self, data):
        """
        Encrypt data using the selected mode.

        Args:
            data (bytes or str): The data to encrypt.

        Returns:
            dict: A dictionary containing the encrypted data and necessary parameters for decryption.
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        iv = os.urandom(16)  # 16 bytes = 128 bits

        if self.mode == "CTR":
            # CTR mode is generally faster as it doesn't require padding and is parallelizable
            cipher = Cipher(algorithms.AES(self.key), modes.CTR(iv), backend=self.backend)
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()

            return {
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                'iv': base64.b64encode(iv).decode('utf-8'),
                'mode': self.mode
            }
        elif self.mode == "CBC":
            # Add padding for CBC mode
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()

            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

            return {
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                'iv': base64.b64encode(iv).decode('utf-8'),
                'mode': self.mode
            }
        elif self.mode == "GCM":
            cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv), backend=self.backend)
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()
            tag = encryptor.tag

            return {
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                'iv': base64.b64encode(iv).decode('utf-8'),
                'tag': base64.b64encode(tag).decode('utf-8'),
                'mode': self.mode
            }
        else:
            raise ValueError(f"Unsupported mode: {self.mode}. Use 'CTR', 'CBC' or 'GCM'.")

    def decrypt(self, encrypted_data):
        """
        Decrypt data using the selected mode.

        Args:
            encrypted_data (dict): Dictionary containing encrypted data and parameters.

        Returns:
            bytes: The decrypted data.
        """
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        iv = base64.b64decode(encrypted_data['iv'])
        mode = encrypted_data.get('mode', self.mode)

        if mode == "CTR":
            cipher = Cipher(algorithms.AES(self.key), modes.CTR(iv), backend=self.backend)
            decryptor = cipher.decryptor()
            data = decryptor.update(ciphertext) + decryptor.finalize()
            return data
        elif mode == "CBC":
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()

            # Remove padding
            unpadder = padding.PKCS7(128).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()

            return data
        elif mode == "GCM":
            tag = base64.b64decode(encrypted_data['tag'])
            cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv, tag), backend=self.backend)
            decryptor = cipher.decryptor()
            data = decryptor.update(ciphertext) + decryptor.finalize()

            return data
        else:
            raise ValueError(f"Unsupported mode: {mode}. Use 'CTR', 'CBC' or 'GCM'.")

    def get_key_base64(self):
        """
        Get the encryption key encoded in base64.

        Returns:
            str: The base64-encoded key.
        """
        return base64.b64encode(self.key).decode('utf-8')

    @classmethod
    def from_base64_key(cls, key_base64, mode="CTR"):
        """
        Create a SymmetricEncryption instance from a base64-encoded key.

        Args:
            key_base64 (str): The base64-encoded key.
            mode (str, optional): Encryption mode, "CTR", "CBC" or "GCM". Defaults to "CTR".

        Returns:
            SymmetricEncryption: A new SymmetricEncryption instance.
        """
        key = base64.b64decode(key_base64)
        return cls(key=key, mode=mode)