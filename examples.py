#!/usr/bin/env python3
"""
Example script demonstrating the use of the Crypto Safety package.
This script shows how to use the main features of the package.
"""

import base64
import os
import time

# Import the Crypto Safety components
from crypto_safety import SymmetricEncryption, AsymmetricEncryption, HashingFunctions, FastCrypto

def symmetric_encryption_example():
    """Demonstrate symmetric encryption."""
    print("\n=== Symmetric Encryption Example ===")

    # Create a new encryption object with a generated key using CTR mode (fastest)
    symmetric = SymmetricEncryption(mode="CTR")
    print(f"Generated new AES-128 key in {symmetric.mode} mode")

    # Save the key (in a real application, store this securely)
    key_b64 = base64.b64encode(symmetric.key).decode('utf-8')
    print(f"Key (base64): {key_b64}")

    # Encrypt some data
    message = "This is a secret message that needs to be encrypted."
    print(f"\nOriginal message: {message}")

    encrypted_data = symmetric.encrypt(message)
    print(f"Encrypted (base64): {encrypted_data}")

    # Decrypt the data
    decrypted_data = symmetric.decrypt(encrypted_data)
    print(f"Decrypted: {decrypted_data.decode('utf-8')}")

    # Try different modes
    print("\nTrying different modes:")
    for mode in ["CBC", "GCM"]:
        start_time = time.time()
        sym = SymmetricEncryption(mode=mode)
        encrypted = sym.encrypt(message)
        decrypted = sym.decrypt(encrypted)
        duration = time.time() - start_time
        print(f"  {mode}: Encryption+Decryption took {duration*1000:.2f}ms")

def asymmetric_encryption_example():
    """Demonstrate asymmetric encryption."""
    print("\n=== Asymmetric Encryption Example ===")

    # Generate a new keypair
    print("Generating 1024-bit RSA keypair...")
    start_time = time.time()
    asymmetric = AsymmetricEncryption(key_size=1024)
    keygen_time = time.time() - start_time
    print(f"Keypair generated in {keygen_time:.2f} seconds")

    # Export the keys
    private_key = asymmetric.export_private_key()
    public_key = asymmetric.export_public_key()

    print(f"\nPrivate key length: {len(private_key)} bytes")
    print(f"Public key length: {len(public_key)} bytes")

    # Encrypt a message
    message = "This message will be encrypted with RSA."
    print(f"\nOriginal message: {message}")

    start_time = time.time()
    encrypted_data = asymmetric.encrypt(message)
    encrypt_time = time.time() - start_time
    print(f"Encrypted (base64): {encrypted_data}")
    print(f"Encryption took {encrypt_time*1000:.2f}ms")

    # Decrypt the message
    start_time = time.time()
    decrypted_data = asymmetric.decrypt(encrypted_data)
    decrypt_time = time.time() - start_time
    print(f"Decrypted: {decrypted_data.decode('utf-8')}")
    print(f"Decryption took {decrypt_time*1000:.2f}ms")

    # Digital signature
    document = "This document needs to be signed to verify its authenticity."
    print(f"\nDocument to sign: {document}")

    start_time = time.time()
    signature = asymmetric.sign(document)
    sign_time = time.time() - start_time
    print(f"Signature (base64): {signature}")
    print(f"Signing took {sign_time*1000:.2f}ms")

    # Verify the signature
    start_time = time.time()
    is_valid = asymmetric.verify(document, signature)
    verify_time = time.time() - start_time
    print(f"Signature valid: {is_valid}")
    print(f"Verification took {verify_time*1000:.2f}ms")

    # Try with a modified document
    modified_document = document + " (modified)"
    is_valid = asymmetric.verify(modified_document, signature)
    print(f"Modified document signature valid: {is_valid} (should be False)")

def hashing_example():
    """Demonstrate hashing functions."""
    print("\n=== Hashing Example ===")

    hasher = HashingFunctions()

    # Data to hash
    data = "This data will be hashed with various algorithms."
    print(f"Data to hash: {data}")

    # Calculate hashes with different algorithms
    print("\nHash values:")

    start_time = time.time()
    md5_hash = hasher.md5(data)
    md5_time = time.time() - start_time
    print(f"  MD5: {md5_hash} ({md5_time*1000:.2f}ms)")

    start_time = time.time()
    sha1_hash = hasher.sha1(data)
    sha1_time = time.time() - start_time
    print(f"  SHA-1: {sha1_hash} ({sha1_time*1000:.2f}ms)")

    start_time = time.time()
    sha256_hash = hasher.sha256(data)
    sha256_time = time.time() - start_time
    print(f"  SHA-256: {sha256_hash} ({sha256_time*1000:.2f}ms)")

    start_time = time.time()
    blake2b_hash = hasher.blake2b(data)
    blake2b_time = time.time() - start_time
    print(f"  BLAKE2b: {blake2b_hash} ({blake2b_time*1000:.2f}ms)")

    # Password hashing
    password = "secure_password123"
    print(f"\nPassword to hash: {password}")

    # PBKDF2 (fast)
    start_time = time.time()
    pbkdf2_hash = hasher.pbkdf2_hash_password(password, iterations=10000, hash_name='sha1')
    pbkdf2_time = time.time() - start_time
    print(f"PBKDF2 hash: {pbkdf2_hash}")
    print(f"PBKDF2 hashing took {pbkdf2_time*1000:.2f}ms")

    # Verify the password
    start_time = time.time()
    is_valid = hasher.verify_pbkdf2_password(password, pbkdf2_hash)
    verify_time = time.time() - start_time
    print(f"Password valid: {is_valid}")
    print(f"Verification took {verify_time*1000:.2f}ms")

def fast_crypto_example():
    """Demonstrate the fast crypto module."""
    print("\n=== Fast Crypto Example ===")

    fast = FastCrypto()

    # Fast encryption
    message = "This message needs to be encrypted very quickly."
    print(f"Message to encrypt: {message}")

    start_time = time.time()
    encrypted = fast.aes_ctr_encrypt(message)
    encrypt_time = time.time() - start_time
    print(f"Encrypted (base64): {encrypted}")
    print(f"Fast encryption took {encrypt_time*1000:.2f}ms")

    # Fast decryption
    start_time = time.time()
    decrypted = fast.aes_ctr_decrypt(encrypted)
    decrypt_time = time.time() - start_time
    print(f"Decrypted: {decrypted.decode('utf-8')}")
    print(f"Fast decryption took {decrypt_time*1000:.2f}ms")

    # Fast hashing
    data = "This data needs to be hashed quickly."
    print(f"\nData to hash: {data}")

    start_time = time.time()
    md5_hash = fast.fast_hash(data, algorithm='md5')
    md5_time = time.time() - start_time
    print(f"MD5 hash: {md5_hash} ({md5_time*1000:.2f}ms)")

    start_time = time.time()
    sha1_hash = fast.fast_hash(data, algorithm='sha1')
    sha1_time = time.time() - start_time
    print(f"SHA-1 hash: {sha1_hash} ({sha1_time*1000:.2f}ms)")

    # Run a mini benchmark
    print("\nRunning a quick benchmark...")
    results = fast.benchmark(iterations=10)

    print("Results:")
    print(f"  AES-CTR Encryption: {results['aes_ctr_encrypt']['mb_per_second']:.2f} MB/sec")
    print(f"  MD5 Hashing: {results['md5_hash']['mb_per_second']:.2f} MB/sec")
    print(f"  SHA-1 Hashing: {results['sha1_hash']['mb_per_second']:.2f} MB/sec")
    print(f"  RSA Operations:")
    print(f"    - Key Generation: {results['rsa_keygen']['operations_per_second']:.2f} op/sec")
    print(f"    - Encryption: {results['rsa_encrypt']['operations_per_second']:.2f} op/sec")
    print(f"    - Decryption: {results['rsa_decrypt']['operations_per_second']:.2f} op/sec")

def main():
    """Main function."""
    print("Crypto Safety Package Examples")
    print("=============================")

    # Run examples
    symmetric_encryption_example()
    asymmetric_encryption_example()
    hashing_example()
    fast_crypto_example()

    print("\nAll examples completed successfully!")

if __name__ == '__main__':
    main()
