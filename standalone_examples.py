#!/usr/bin/env python3
"""
Standalone example script for the Crypto Safety toolkit.
This script demonstrates the key features without relying on external dependencies.
"""

import base64
import os
import time
import hashlib
import sys

def print_header():
    """Print the header for the example script."""
    print("=" * 50)
    print("  Crypto Safety Toolkit - Standalone Examples")
    print("=" * 50)
    print("This script demonstrates the core functionality of the toolkit")
    print("without requiring external dependencies.")
    print()

def symmetric_encryption_example():
    """Demonstrate symmetric encryption using a simple XOR cipher."""
    print("\n=== Symmetric Encryption Example ===")

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
    start_time = time.time()
    encrypted = xor_encrypt(message.encode('utf-8'), key)
    encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')
    encrypt_time = time.time() - start_time
    print(f"Encrypted (base64): {encrypted_b64}")
    print(f"Encryption took {encrypt_time*1000:.2f}ms")

    # Decrypt message (XOR is its own inverse)
    start_time = time.time()
    decrypted = xor_encrypt(encrypted, key)
    decrypt_time = time.time() - start_time
    print(f"Decrypted message: {decrypted.decode('utf-8')}")
    print(f"Decryption took {decrypt_time*1000:.2f}ms")

def hashing_example():
    """Demonstrate various hashing algorithms."""
    print("\n=== Hashing Functions Example ===")

    # Data to hash
    data = "This is sensitive data that needs to be hashed."
    print(f"Original data: {data}")

    # Calculate various hashes
    start_time = time.time()
    md5_hash = hashlib.md5(data.encode('utf-8')).hexdigest()
    md5_time = time.time() - start_time

    start_time = time.time()
    sha1_hash = hashlib.sha1(data.encode('utf-8')).hexdigest()
    sha1_time = time.time() - start_time

    start_time = time.time()
    sha256_hash = hashlib.sha256(data.encode('utf-8')).hexdigest()
    sha256_time = time.time() - start_time

    start_time = time.time()
    sha512_hash = hashlib.sha512(data.encode('utf-8')).hexdigest()
    sha512_time = time.time() - start_time

    print(f"\nMD5 ({md5_time*1000:.2f}ms): {md5_hash}")
    print(f"SHA-1 ({sha1_time*1000:.2f}ms): {sha1_hash}")
    print(f"SHA-256 ({sha256_time*1000:.2f}ms): {sha256_hash}")
    print(f"SHA-512 ({sha512_time*1000:.2f}ms): {sha512_hash}")

def simplified_rsa_example():
    """Demonstrate a simplified RSA encryption."""
    print("\n=== Simplified RSA Example ===")

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

    # Simple key generation with small primes (for demonstration only)
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
    start_time = time.time()
    encrypted = pow(message, e, n)
    encrypt_time = time.time() - start_time
    print(f"Encrypted message: {encrypted}")
    print(f"Encryption took {encrypt_time*1000:.2f}ms")

    # Decrypt message
    start_time = time.time()
    decrypted = pow(encrypted, d, n)
    decrypt_time = time.time() - start_time
    print(f"Decrypted message: {decrypted}")
    print(f"Decryption took {decrypt_time*1000:.2f}ms")

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

def demo_all():
    """Run all examples."""
    print_header()
    symmetric_encryption_example()
    hashing_example()
    simplified_rsa_example()
    benchmark_hashing()
    print("\nAll examples completed successfully!")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description='Crypto Safety Toolkit - Standalone Examples'
    )
    parser.add_argument('--symmetric', action='store_true', help='Run symmetric encryption example')
    parser.add_argument('--hash', action='store_true', help='Run hashing example')
    parser.add_argument('--rsa', action='store_true', help='Run simplified RSA example')
    parser.add_argument('--benchmark', action='store_true', help='Run benchmarks')
    parser.add_argument('--all', action='store_true', help='Run all examples')

    args = parser.parse_args()

    # If no arguments are provided, run all examples
    if not any(vars(args).values()):
        demo_all()
        sys.exit(0)

    if args.all:
        demo_all()
        sys.exit(0)

    if args.symmetric:
        symmetric_encryption_example()

    if args.hash:
        hashing_example()

    if args.rsa:
        simplified_rsa_example()

    if args.benchmark:
        benchmark_hashing()
