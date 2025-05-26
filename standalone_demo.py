#!/usr/bin/env python3
"""
Standalone demo for Crypto Safety toolkit.
This script provides a demonstration of cryptographic operations without
requiring the full crypto_safety package.
"""

import time
import hashlib
import base64
import os
import sys

def demo_symmetric_encryption():
    """Demonstrate symmetric encryption using a simple XOR cipher."""
    print("\n=== Simple Symmetric Encryption Demo ===")

    # Generate a random key
    key = os.urandom(16)
    key_b64 = base64.b64encode(key).decode('utf-8')
    print(f"Generated key (base64): {key_b64}")

    # Simple XOR encryption function
    def xor_encrypt(data, key):
        if isinstance(data, str):
            data = data.encode('utf-8')
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

    # Message to encrypt
    message = "This is a secret message that needs to be encrypted."
    print(f"\nOriginal message: {message}")

    # Encrypt message
    encrypted = xor_encrypt(message.encode('utf-8'), key)
    encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')
    print(f"Encrypted (base64): {encrypted_b64}")

    # Decrypt message (XOR is its own inverse)
    decrypted = xor_encrypt(encrypted, key)
    print(f"Decrypted message: {decrypted.decode('utf-8')}")

    return True

def demo_hashing():
    """Demonstrate various hashing algorithms."""
    print("\n=== Hashing Functions Demo ===")

    # Data to hash
    data = "This is the data to be hashed."
    print(f"Original data: {data}")

    # Calculate various hashes
    md5_hash = hashlib.md5(data.encode('utf-8')).hexdigest()
    sha1_hash = hashlib.sha1(data.encode('utf-8')).hexdigest()
    sha256_hash = hashlib.sha256(data.encode('utf-8')).hexdigest()
    sha512_hash = hashlib.sha512(data.encode('utf-8')).hexdigest()

    print(f"\nMD5 (fast but less secure): {md5_hash}")
    print(f"SHA-1 (faster with reasonable security): {sha1_hash}")
    print(f"SHA-256 (good balance of security and speed): {sha256_hash}")
    print(f"SHA-512 (most secure but slower): {sha512_hash}")

    return True

def benchmark_hashing():
    """Benchmark hashing functions."""
    print("\n=== Hashing Functions Benchmark ===")

    # Generate some data to hash (1 MB)
    data = os.urandom(1024 * 1024)
    iterations = 100

    # Benchmark MD5
    start_time = time.time()
    for _ in range(iterations):
        hashlib.md5(data).digest()
    md5_time = time.time() - start_time
    md5_mb_per_sec = iterations / md5_time

    # Benchmark SHA-1
    start_time = time.time()
    for _ in range(iterations):
        hashlib.sha1(data).digest()
    sha1_time = time.time() - start_time
    sha1_mb_per_sec = iterations / sha1_time

    # Benchmark SHA-256
    start_time = time.time()
    for _ in range(iterations):
        hashlib.sha256(data).digest()
    sha256_time = time.time() - start_time
    sha256_mb_per_sec = iterations / sha256_time

    # Benchmark SHA-512
    start_time = time.time()
    for _ in range(iterations):
        hashlib.sha512(data).digest()
    sha512_time = time.time() - start_time
    sha512_mb_per_sec = iterations / sha512_time

    print(f"Data size: 1 MB, Iterations: {iterations}")
    print(f"MD5: {md5_mb_per_sec:.2f} MB/s")
    print(f"SHA-1: {sha1_mb_per_sec:.2f} MB/s")
    print(f"SHA-256: {sha256_mb_per_sec:.2f} MB/s")
    print(f"SHA-512: {sha512_mb_per_sec:.2f} MB/s")

    # Speed comparison
    base = sha256_mb_per_sec
    print("\nSpeed compared to SHA-256:")
    print(f"MD5: {md5_mb_per_sec/base:.2f}x faster")
    print(f"SHA-1: {sha1_mb_per_sec/base:.2f}x faster")
    print(f"SHA-512: {sha512_mb_per_sec/base:.2f}x faster")

    return True

def demo_simple_rsa():
    """Demonstrate a simplified RSA encryption."""
    print("\n=== Simplified RSA Demo ===")

    try:
        # Simple math functions for RSA
        def gcd(a, b):
            while b:
                a, b = b, a % b
            return a

        def mod_inverse(e, phi):
            for d in range(3, phi):
                if (d * e) % phi == 1:
                    return d
            return None

        # Simple key generation with very small primes (not secure, for demo only!)
        p, q = 61, 53
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 17  # Public exponent
        d = mod_inverse(e, phi)  # Private exponent

        print(f"Generated key pair with small primes (p={p}, q={q}):")
        print(f"Public key (e, n): ({e}, {n})")
        print(f"Private key (d, n): ({d}, {n})")

        # Message to encrypt (must be smaller than n)
        message = 42
        print(f"\nOriginal message (integer): {message}")

        # Encrypt message
        encrypted = pow(message, e, n)
        print(f"Encrypted message: {encrypted}")

        # Decrypt message
        decrypted = pow(encrypted, d, n)
        print(f"Decrypted message: {decrypted}")

        return True
    except Exception as e:
        print(f"Error in RSA demo: {e}")
        return False

def main():
    """Main function."""
    print("Crypto Safety - Standalone Demo")
    print("=================================")

    demos = [
        demo_symmetric_encryption,
        demo_hashing,
        demo_simple_rsa,
        benchmark_hashing
    ]

    success = True
    for demo in demos:
        try:
            result = demo()
            if not result:
                success = False
        except Exception as e:
            print(f"Error running demo {demo.__name__}: {e}")
            success = False

    if success:
        print("\nAll demos completed successfully!")
    else:
        print("\nSome demos failed. See error messages above.")

    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
