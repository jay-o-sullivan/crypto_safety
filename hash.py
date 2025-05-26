from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
import hashlib
import os
import base64


class HashingFunctions:
    """
    A class for secure hashing operations.
    Provides various hash functions, HMAC creation, and password hashing.
    """

    def __init__(self):
        """
        Initialize the hashing functions class.
        """
        self.backend = default_backend()

    def md5(self, data):
        """
        Create an MD5 hash of the data. Fast but less secure.
        Note: Use only for checksums, not for security purposes.

        Args:
            data (bytes or str): The data to hash.

        Returns:
            bytes: The MD5 hash digest.
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        digest = hashes.Hash(hashes.MD5(), backend=self.backend)
        digest.update(data)
        return digest.finalize()

    def sha1(self, data):
        """
        Create a SHA-1 hash of the data. Fast but less secure.
        Note: Use only when performance is critical, not for high security needs.

        Args:
            data (bytes or str): The data to hash.

        Returns:
            bytes: The SHA-1 hash digest.
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        digest = hashes.Hash(hashes.SHA1(), backend=self.backend)
        digest.update(data)
        return digest.finalize()

    def sha256(self, data):
        """
        Create a SHA-256 hash of the data.

        Args:
            data (bytes or str): The data to hash.

        Returns:
            bytes: The SHA-256 hash digest.
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        digest = hashes.Hash(hashes.SHA256(), backend=self.backend)
        digest.update(data)
        return digest.finalize()

    def sha512(self, data):
        """
        Create a SHA-512 hash of the data.

        Args:
            data (bytes or str): The data to hash.

        Returns:
            bytes: The SHA-512 hash digest.
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        digest = hashes.Hash(hashes.SHA512(), backend=self.backend)
        digest.update(data)
        return digest.finalize()

    def blake2b(self, data, digest_size=64):
        """
        Create a BLAKE2b hash of the data.

        Args:
            data (bytes or str): The data to hash.
            digest_size (int, optional): The size of the digest in bytes. Defaults to 64.

        Returns:
            bytes: The BLAKE2b hash digest.
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        digest = hashes.Hash(hashes.BLAKE2b(digest_size), backend=self.backend)
        digest.update(data)
        return digest.finalize()

    def create_hmac(self, key, data, algorithm='sha1'):
        """
        Create an HMAC for the data using the specified key and algorithm.

        Args:
            key (bytes or str): The key to use for the HMAC.
            data (bytes or str): The data to create an HMAC for.
            algorithm (str, optional): The hash algorithm to use. Defaults to 'sha1' for speed.

        Returns:
            bytes: The HMAC digest.
        """
        if isinstance(key, str):
            key = key.encode('utf-8')
        if isinstance(data, str):
            data = data.encode('utf-8')

        hash_algorithm = None
        if algorithm.lower() == 'md5':
            hash_algorithm = hashes.MD5()
        elif algorithm.lower() == 'sha1':
            hash_algorithm = hashes.SHA1()
        elif algorithm.lower() == 'sha256':
            hash_algorithm = hashes.SHA256()
        elif algorithm.lower() == 'sha512':
            hash_algorithm = hashes.SHA512()
        elif algorithm.lower() == 'blake2b':
            hash_algorithm = hashes.BLAKE2b(64)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        h = hmac.HMAC(key, hash_algorithm, backend=self.backend)
        h.update(data)
        return h.finalize()

    def verify_hmac(self, key, data, signature, algorithm='sha1'):
        """
        Verify an HMAC signature.

        Args:
            key (bytes or str): The key used to create the HMAC.
            data (bytes or str): The data that was signed.
            signature (bytes): The HMAC signature to verify.
            algorithm (str, optional): The hash algorithm used. Defaults to 'sha1' for speed.

        Returns:
            bool: True if the signature is valid, False otherwise.
        """
        expected_hmac = self.create_hmac(key, data, algorithm)

        # Try to use constant-time comparison to prevent timing attacks
        try:
            # Python 3.3+ has hmac.compare_digest
            return hmac.compare_digest(expected_hmac, signature)
        except AttributeError:
            # For older Python versions, use a simple comparison
            # Note: This is not constant-time and may be vulnerable to timing attacks
            return expected_hmac == signature

    def pbkdf2_hash_password(self, password, salt=None, iterations=10000, hash_name='sha1'):
        """
        Hash a password using PBKDF2 (Password-Based Key Derivation Function 2).
        Using fewer iterations and SHA1 for faster performance.

        Args:
            password (str or bytes): The password to hash.
            salt (bytes, optional): The salt to use. If None, a random salt will be generated.
            iterations (int, optional): The number of iterations. Defaults to 10000 for better performance.
            hash_name (str, optional): The hash algorithm to use. Defaults to 'sha1' for speed.

        Returns:
            dict: A dictionary containing the hash, salt, iterations, and hash_name.
        """
        if isinstance(password, str):
            password = password.encode('utf-8')

        if salt is None:
            salt = os.urandom(16)  # 16 bytes = 128 bits

        # Use hashlib's pbkdf2_hmac function
        password_hash = hashlib.pbkdf2_hmac(
            hash_name,
            password,
            salt,
            iterations,
            32  # 32 bytes = 256 bits (reduced from 512 for speed)
        )

        return {
            'hash': base64.b64encode(password_hash).decode('utf-8'),
            'salt': base64.b64encode(salt).decode('utf-8'),
            'iterations': iterations,
            'hash_name': hash_name
        }

    def verify_pbkdf2_password(self, password, password_hash_dict):
        """
        Verify a password against a PBKDF2 hash.

        Args:
            password (str or bytes): The password to verify.
            password_hash_dict (dict): The dictionary containing the hash information.

        Returns:
            bool: True if the password matches, False otherwise.
        """
        if isinstance(password, str):
            password = password.encode('utf-8')

        salt = base64.b64decode(password_hash_dict['salt'])
        iterations = password_hash_dict['iterations']
        hash_name = password_hash_dict['hash_name']
        stored_hash = base64.b64decode(password_hash_dict['hash'])

        # Compute the hash of the provided password
        computed_hash = hashlib.pbkdf2_hmac(
            hash_name,
            password,
            salt,
            iterations,
            len(stored_hash)
        )

        # Use a constant-time comparison to prevent timing attacks
        try:
            return hmac.compare_digest(computed_hash, stored_hash)
        except AttributeError:
            return computed_hash == stored_hash

    def argon2_hash_password(self, password, time_cost=1, memory_cost=65536, parallelism=4):
        """
        Hash a password using Argon2, a more memory-hard hash function than PBKDF2.
        Note: Requires the 'argon2-cffi' package to be installed.

        Using lower time_cost and memory_cost for better performance.

        Args:
            password (str or bytes): The password to hash.
            time_cost (int, optional): Time cost parameter. Defaults to 1 for speed.
            memory_cost (int, optional): Memory cost in KiB. Defaults to 65536 (64MB).
            parallelism (int, optional): Parallelism factor. Defaults to 4.

        Returns:
            str: The Argon2 hash as a string.
        """
        try:
            # Only import if needed
            from argon2 import PasswordHasher

            if isinstance(password, str):
                password = password.encode('utf-8')

            ph = PasswordHasher(
                time_cost=time_cost,
                memory_cost=memory_cost,
                parallelism=parallelism
            )
            hash_str = ph.hash(password)

            return hash_str

        except ImportError:
            raise ImportError("The 'argon2-cffi' package is required for Argon2 hashing. "
                             "Install it with: pip install argon2-cffi")

    def verify_argon2_password(self, password, hash_str):
        """
        Verify a password against an Argon2 hash.
        Note: Requires the 'argon2-cffi' package to be installed.

        Args:
            password (str or bytes): The password to verify.
            hash_str (str): The Argon2 hash string.

        Returns:
            bool: True if the password matches, False otherwise.
        """
        try:
            # Only import if needed
            from argon2 import PasswordHasher
            from argon2.exceptions import VerifyMismatchError

            if isinstance(password, str):
                password = password.encode('utf-8')

            ph = PasswordHasher()

            try:
                ph.verify(hash_str, password)
                return True
            except VerifyMismatchError:
                return False

        except ImportError:
            raise ImportError("The 'argon2-cffi' package is required for Argon2 hashing. "
                             "Install it with: pip install argon2-cffi")