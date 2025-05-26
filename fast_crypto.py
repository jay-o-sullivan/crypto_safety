"""
Fast implementations of cryptographic operations.
This module focuses on speed over maximum security.
"""

import os
import base64
import time
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class FastCrypto:
    """
    A class for extremely fast cryptographic operations.
    Uses the fastest algorithms and configurations available.

    IMPORTANT: These implementations prioritize speed over security.
    Use only for non-sensitive data or where performance is critical.
    """

    def __init__(self):
        """
        Initialize the fast crypto object.
        """
        self.backend = default_backend()

    def aes_ctr_encrypt(self, data, key=None):
        """
        Encrypt data using AES-128 in CTR mode (fastest AES mode).

        Args:
            data (bytes or str): Data to encrypt
            key (bytes, optional): 16-byte key. If None, a random key is generated.

        Returns:
            dict: Contains 'ciphertext', 'key', and 'nonce' (all base64 encoded)
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        if key is None:
            key = os.urandom(16)  # 128-bit key (fastest)
        elif len(key) != 16:
            raise ValueError("Key must be 16 bytes (128 bits) for AES-128")

        nonce = os.urandom(16)

        # Create AES cipher in CTR mode (fastest mode, parallelizable)
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=self.backend)
        encryptor = cipher.encryptor()

        # Encrypt data
        ciphertext = encryptor.update(data) + encryptor.finalize()

        return {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'key': base64.b64encode(key).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8')
        }

    def aes_ctr_decrypt(self, encrypted_data):
        """
        Decrypt data using AES-128 in CTR mode.

        Args:
            encrypted_data (dict): Dictionary containing 'ciphertext', 'key', and 'nonce'

        Returns:
            bytes: Decrypted data
        """
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        key = base64.b64decode(encrypted_data['key'])
        nonce = base64.b64decode(encrypted_data['nonce'])

        # Create AES cipher in CTR mode
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=self.backend)
        decryptor = cipher.decryptor()

        # Decrypt data
        return decryptor.update(ciphertext) + decryptor.finalize()

    def fast_hash(self, data, algorithm='md5'):
        """
        Create a fast hash of data.

        Args:
            data (str or bytes): Data to hash
            algorithm (str): Hash algorithm - 'md5' (fastest), 'sha1', or 'sha256'

        Returns:
            str: Hexadecimal hash digest
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        if algorithm == 'md5':
            # MD5 is the fastest but least secure
            return hashlib.md5(data).hexdigest()
        elif algorithm == 'sha1':
            # SHA-1 is fast with reasonable security
            return hashlib.sha1(data).hexdigest()
        elif algorithm == 'sha256':
            # SHA-256 is slower but more secure
            return hashlib.sha256(data).hexdigest()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

    def benchmark(self, data_size=1024*1024):
        """
        Benchmark cryptographic operations.

        Args:
            data_size (int): Size of random data to use for benchmarking

        Returns:
            dict: Benchmark results in operations per second
        """
        # Generate random data
        data = os.urandom(data_size)  # 1MB by default
        key = os.urandom(16)

        results = {}

        # Benchmark AES-CTR encryption
        iterations = 10
        start_time = time.time()
        for _ in range(iterations):
            encrypted = self.aes_ctr_encrypt(data, key)
        end_time = time.time()
        results['aes_ctr_encrypt'] = {
            'ops_per_second': iterations / (end_time - start_time),
            'mb_per_second': (data_size * iterations) / (1024 * 1024) / (end_time - start_time)
        }

        # Benchmark AES-CTR decryption
        start_time = time.time()
        for _ in range(iterations):
            self.aes_ctr_decrypt(encrypted)
        end_time = time.time()
        results['aes_ctr_decrypt'] = {
            'ops_per_second': iterations / (end_time - start_time),
            'mb_per_second': (data_size * iterations) / (1024 * 1024) / (end_time - start_time)
        }

        # Benchmark hashing (MD5, SHA-1, SHA-256)
        for algo in ['md5', 'sha1', 'sha256']:
            start_time = time.time()
            for _ in range(iterations):
                self.fast_hash(data, algorithm=algo)
            end_time = time.time()
            results[f'{algo}_hash'] = {
                'ops_per_second': iterations / (end_time - start_time),
                'mb_per_second': (data_size * iterations) / (1024 * 1024) / (end_time - start_time)
            }

        return results


def demonstrate_fast_crypto():
    """
    Demonstrate the fast crypto operations.
    """
    print("\n=== Fast Crypto Demonstration ===")

    fast = FastCrypto()

    # Demonstrate fast encryption/decryption
    message = "This is a test message for fast encryption."
    print(f"Original message: {message}")

    start_time = time.time()
    encrypted = fast.aes_ctr_encrypt(message)
    encryption_time = time.time() - start_time

    print(f"Encrypted (AES-128-CTR): {encrypted['ciphertext']}")
    print(f"Encryption time: {encryption_time:.6f} seconds")

    start_time = time.time()
    decrypted = fast.aes_ctr_decrypt(encrypted)
    decryption_time = time.time() - start_time

    print(f"Decrypted: {decrypted.decode('utf-8')}")
    print(f"Decryption time: {decryption_time:.6f} seconds")

    # Demonstrate fast hashing
    print("\n--- Fast Hashing ---")

    for algo in ['md5', 'sha1', 'sha256']:
        start_time = time.time()
        hash_result = fast.fast_hash(message, algorithm=algo)
        hash_time = time.time() - start_time

        print(f"{algo.upper()}: {hash_result}")
        print(f"{algo.upper()} hashing time: {hash_time:.6f} seconds")

    # Benchmark operations on larger data
    print("\n--- Benchmarking (1MB data) ---")

    benchmark_results = fast.benchmark()

    for operation, metrics in benchmark_results.items():
        print(f"{operation}: {metrics['ops_per_second']:.2f} ops/sec ({metrics['mb_per_second']:.2f} MB/sec)")


if __name__ == "__main__":
    demonstrate_fast_crypto()
