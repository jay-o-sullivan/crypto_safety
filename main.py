import os
import json
import time
from symmetric import SymmetricEncryption
from asymmetric import AsymmetricEncryption
from hash import HashingFunctions
from fast_crypto import FastCrypto, demonstrate_fast_crypto


def demonstrate_symmetric_encryption():
    """Demonstrate the use of symmetric encryption."""
    print("\n=== Symmetric Encryption Demonstration (Optimized for Speed) ===")

    # Create a symmetric encryption object with a generated key using CTR mode
    symmetric = SymmetricEncryption(mode="CTR")
    print(f"Generated Key (Base64): {symmetric.get_key_base64()}")
    print(f"Using AES-128 with CTR mode (fast and parallelizable)")

    # Encrypt some data
    message = "This is a secret message that needs to be encrypted."

    # Measure encryption speed
    start_time = time.time()
    encrypted_data = symmetric.encrypt(message)
    encryption_time = time.time() - start_time

    print(f"Encrypted Data: {json.dumps(encrypted_data, indent=2)}")
    print(f"Encryption Time: {encryption_time:.6f} seconds")

    # Decrypt the data
    start_time = time.time()
    decrypted_data = symmetric.decrypt(encrypted_data)
    decryption_time = time.time() - start_time

    print(f"Decrypted Message: {decrypted_data.decode('utf-8')}")
    print(f"Decryption Time: {decryption_time:.6f} seconds")

    # Compare with CBC mode
    print("\n--- Comparing with CBC Mode ---")
    symmetric_cbc = SymmetricEncryption(mode="CBC")

    start_time = time.time()
    encrypted_data_cbc = symmetric_cbc.encrypt(message)
    cbc_encryption_time = time.time() - start_time

    start_time = time.time()
    decrypted_data_cbc = symmetric_cbc.decrypt(encrypted_data_cbc)
    cbc_decryption_time = time.time() - start_time

    print(f"CBC Encryption Time: {cbc_encryption_time:.6f} seconds")
    print(f"CBC Decryption Time: {cbc_decryption_time:.6f} seconds")

    # Avoid division by zero by checking timing values
    if encryption_time > 0 and cbc_encryption_time > 0:
        print(f"Speed Improvement (Encryption): {(cbc_encryption_time/encryption_time):.2f}x faster")
    else:
        print("Speed Improvement (Encryption): Unable to measure (too fast)")

    if decryption_time > 0 and cbc_decryption_time > 0:
        print(f"Speed Improvement (Decryption): {(cbc_decryption_time/decryption_time):.2f}x faster")
    else:
        print("Speed Improvement (Decryption): Unable to measure (too fast)")


def demonstrate_asymmetric_encryption():
    """Demonstrate the use of asymmetric encryption."""
    print("\n=== Asymmetric Encryption Demonstration (Optimized for Speed) ===")

    # Create an asymmetric encryption object with a smaller key size
    start_time = time.time()
    asymmetric = AsymmetricEncryption(key_size=1024)
    key_gen_time = time.time() - start_time

    print(f"Generated 1024-bit RSA Key Pair in {key_gen_time:.6f} seconds")

    # Export the keys (this would typically be done once and saved)
    private_key_pem = asymmetric.export_private_key()
    public_key_pem = asymmetric.export_public_key()

    print("Generated RSA Key Pair:")
    print(f"Private Key:\n{private_key_pem[:100]}... [truncated]")
    print(f"Public Key:\n{public_key_pem[:100]}... [truncated]")

    # Encrypt a message with the public key
    message = "This message is encrypted with RSA public key."

    start_time = time.time()
    encrypted_data = asymmetric.encrypt(message)
    encryption_time = time.time() - start_time

    print(f"\nEncrypted Data (Base64): {encrypted_data[:50]}... [truncated]")
    print(f"Encryption Time: {encryption_time:.6f} seconds")

    # Decrypt the message with the private key
    start_time = time.time()
    decrypted_data = asymmetric.decrypt(encrypted_data)
    decryption_time = time.time() - start_time

    print(f"Decrypted Message: {decrypted_data.decode('utf-8')}")
    print(f"Decryption Time: {decryption_time:.6f} seconds")

    # Demonstrate digital signature
    print("\n--- Digital Signature (Using Fast Algorithms) ---")

    document = "This is an important document that needs to be signed."

    start_time = time.time()
    signature = asymmetric.sign(document)
    signing_time = time.time() - start_time

    print(f"Document: {document}")
    print(f"Signature (Base64): {signature[:50]}... [truncated]")
    print(f"Signing Time: {signing_time:.6f} seconds")

    # Verify the signature
    start_time = time.time()
    is_valid = asymmetric.verify(document, signature)
    verification_time = time.time() - start_time

    print(f"Signature valid: {is_valid}")
    print(f"Verification Time: {verification_time:.6f} seconds")

    # Compare with 2048-bit RSA
    print("\n--- Comparing with 2048-bit RSA ---")
    start_time = time.time()
    asymmetric_2048 = AsymmetricEncryption(key_size=2048)
    key_gen_time_2048 = time.time() - start_time

    print(f"2048-bit Key Generation Time: {key_gen_time_2048:.6f} seconds")
    print(f"Speed Improvement: {(key_gen_time_2048/key_gen_time):.2f}x faster")


def demonstrate_hashing():
    """Demonstrate the use of hashing functions."""
    print("\n=== Hashing Demonstration (Optimized for Speed) ===")

    # Create a hashing functions object
    hasher = HashingFunctions()

    # Demonstrate basic hashing with various algorithms
    message = "This is a message to hash."

    print(f"Message: {message}")

    # MD5 (fastest but least secure)
    start_time = time.time()
    md5_hash = hasher.md5(message)
    md5_time = time.time() - start_time
    print(f"MD5 Hash: {md5_hash.hex()}")
    print(f"MD5 Time: {md5_time:.6f} seconds")

    # SHA-1 (fast with reasonable security for non-critical applications)
    start_time = time.time()
    sha1_hash = hasher.sha1(message)
    sha1_time = time.time() - start_time
    print(f"SHA-1 Hash: {sha1_hash.hex()}")
    print(f"SHA-1 Time: {sha1_time:.6f} seconds")

    # SHA-256 (good balance of security and speed)
    start_time = time.time()
    sha256_hash = hasher.sha256(message)
    sha256_time = time.time() - start_time
    print(f"SHA-256 Hash: {sha256_hash.hex()}")
    print(f"SHA-256 Time: {sha256_time:.6f} seconds")

    # SHA-512 (most secure but slower)
    start_time = time.time()
    sha512_hash = hasher.sha512(message)
    sha512_time = time.time() - start_time
    print(f"SHA-512 Hash: {sha512_hash.hex()}")
    print(f"SHA-512 Time: {sha512_time:.6f} seconds")

    print("\nPerformance Comparison (relative to SHA-256):")
    if md5_time > 0 and sha256_time > 0:
        print(f"MD5: {(sha256_time/md5_time):.2f}x faster")
    else:
        print("MD5: Unable to measure (too fast)")

    if sha1_time > 0 and sha256_time > 0:
        print(f"SHA-1: {(sha256_time/sha1_time):.2f}x faster")
    else:
        print("SHA-1: Unable to measure (too fast)")

    if sha256_time > 0 and sha512_time > 0:
        print(f"SHA-512: {(sha512_time/sha256_time):.2f}x slower")
    else:
        print("SHA-512: Unable to measure (too fast)")

    # Demonstrate HMAC with SHA-1 (fast)
    print("\n--- HMAC (Fast Implementation) ---")

    key = os.urandom(16)  # 16 bytes = 128 bits

    start_time = time.time()
    hmac_sha1 = hasher.create_hmac(key, message, algorithm='sha1')
    hmac_time = time.time() - start_time

    print(f"HMAC-SHA1: {hmac_sha1.hex()}")
    print(f"HMAC Computation Time: {hmac_time:.6f} seconds")

    start_time = time.time()
    is_valid = hasher.verify_hmac(key, message, hmac_sha1, algorithm='sha1')
    verify_time = time.time() - start_time

    print(f"HMAC Verification: {is_valid}")
    print(f"Verification Time: {verify_time:.6f} seconds")

    # Demonstrate password hashing with PBKDF2 (fewer iterations for speed)
    print("\n--- Password Hashing with PBKDF2 (Fast Configuration) ---")

    password = "secure_password123"

    start_time = time.time()
    hashed_password = hasher.pbkdf2_hash_password(password, iterations=10000, hash_name='sha1')
    pbkdf2_time = time.time() - start_time

    print(f"Password: {password}")
    print("Hashed Password Info:")
    for key, value in hashed_password.items():
        print(f"  {key}: {value}")
    print(f"Hashing Time: {pbkdf2_time:.6f} seconds")

    # Verify the password
    start_time = time.time()
    is_valid = hasher.verify_pbkdf2_password(password, hashed_password)
    verify_time = time.time() - start_time

    print(f"Correct Password Verification: {is_valid}")
    print(f"Verification Time: {verify_time:.6f} seconds")

    # Compare with more secure but slower settings
    print("\n--- Comparing with More Secure PBKDF2 Settings ---")

    start_time = time.time()
    hashed_password_secure = hasher.pbkdf2_hash_password(password, iterations=100000, hash_name='sha256')
    pbkdf2_secure_time = time.time() - start_time

    print(f"Secure Settings Hashing Time: {pbkdf2_secure_time:.6f} seconds")
    print(f"Speed Improvement: {(pbkdf2_secure_time/pbkdf2_time):.2f}x faster")


def secure_communication_example():
    """Demonstrate a complete example of secure communication using fast algorithms."""
    print("\n=== Secure Communication Example (Optimized for Speed) ===")
    print("This example simulates secure communication between Alice and Bob using fast algorithms.")

    # Alice generates a key pair
    print("\nAlice generates a 1024-bit RSA key pair...")
    start_time = time.time()
    alice_keys = AsymmetricEncryption(key_size=1024)
    alice_time = time.time() - start_time
    alice_public_pem = alice_keys.export_public_key()
    print(f"Key generation time: {alice_time:.6f} seconds")

    # Bob generates a key pair
    print("Bob generates a 1024-bit RSA key pair...")
    start_time = time.time()
    bob_keys = AsymmetricEncryption(key_size=1024)
    bob_time = time.time() - start_time
    bob_public_pem = bob_keys.export_public_key()
    print(f"Key generation time: {bob_time:.6f} seconds")

    # Alice and Bob exchange public keys
    print("Alice and Bob exchange public keys...")

    # Alice creates an instance with Bob's public key
    alice_to_bob = AsymmetricEncryption.from_public_key_pem(bob_public_pem)

    # Bob creates an instance with Alice's public key
    bob_to_alice = AsymmetricEncryption.from_public_key_pem(alice_public_pem)

    # Alice wants to send a secure message to Bob
    print("\nAlice wants to send a secure message to Bob:")

    # Alice generates a random symmetric key using CTR mode for performance
    alice_sym_key = SymmetricEncryption(mode="CTR")
    message = "Hey Bob, this is a secret message that only you should be able to read!"

    # Measure the performance of the hybrid encryption approach
    start_time = time.time()

    # Alice encrypts the message with the symmetric key
    encrypted_message = alice_sym_key.encrypt(message)

    # Alice encrypts the symmetric key with Bob's public key
    encrypted_key = alice_to_bob.encrypt(alice_sym_key.key)

    alice_encryption_time = time.time() - start_time

    # Alice sends the encrypted message and encrypted key to Bob
    print(f"Alice's message: {message}")
    print("Alice encrypts the message with AES-128-CTR, then encrypts that key with Bob's public key.")
    print(f"Encryption time: {alice_encryption_time:.6f} seconds")

    # Bob receives the encrypted message and key
    print("\nBob receives the encrypted message and key:")

    start_time = time.time()

    # Bob decrypts the symmetric key with his private key
    decrypted_key = bob_keys.decrypt(encrypted_key)

    # Bob creates a symmetric encryption object with the decrypted key
    bob_sym_key = SymmetricEncryption(key=decrypted_key, mode="CTR")

    # Bob decrypts the message
    decrypted_message = bob_sym_key.decrypt(encrypted_message)

    bob_decryption_time = time.time() - start_time

    print(f"Bob decrypts the symmetric key using his private key.")
    print(f"Bob uses the symmetric key to decrypt the message: {decrypted_message.decode('utf-8')}")
    print(f"Decryption time: {bob_decryption_time:.6f} seconds")

    # Bob sends a signed response to Alice using the faster PKCS1v15 padding
    print("\nBob sends a signed response to Alice:")

    response = "Hi Alice, I got your message. Let's meet tomorrow!"

    start_time = time.time()
    signature = bob_keys.sign(response)
    signing_time = time.time() - start_time

    print(f"Bob's response: {response}")
    print(f"Bob signs his response with his private key using PKCS1v15 padding and SHA-1.")
    print(f"Signing time: {signing_time:.6f} seconds")

    # Alice verifies the signature and reads the response
    print("\nAlice verifies the signature and reads the response:")

    start_time = time.time()
    is_valid = bob_to_alice.verify(response, signature)
    verification_time = time.time() - start_time

    print(f"Signature valid: {is_valid}")
    print(f"Verification time: {verification_time:.6f} seconds")

    if is_valid:
        print(f"Alice reads Bob's response: {response}")
    else:
        print("Alice rejects the message because the signature is invalid.")

    print("\nPerformance Summary:")
    print(f"Alice's encryption: {alice_encryption_time:.6f} seconds")
    print(f"Bob's decryption: {bob_decryption_time:.6f} seconds")
    print(f"Bob's signing: {signing_time:.6f} seconds")
    print(f"Alice's verification: {verification_time:.6f} seconds")
    print(f"Total communication time: {alice_encryption_time + bob_decryption_time + signing_time + verification_time:.6f} seconds")


def performance_comparison():
    """Compare the performance of different cryptographic algorithms."""
    print("\n=== Performance Comparison ===")

    # Test data of different sizes
    data_sizes = [100, 1000, 10000, 100000, 1000000]  # in bytes

    print("Symmetric Encryption Performance (encryption time in seconds):")
    print("Size (bytes) | AES-128-CTR | AES-128-CBC | AES-128-GCM")
    print("-------------|-------------|-------------|------------")

    for size in data_sizes:
        data = os.urandom(size)

        # Test CTR mode
        sym_ctr = SymmetricEncryption(mode="CTR")
        start_time = time.time()
        sym_ctr.encrypt(data)
        ctr_time = time.time() - start_time

        # Test CBC mode
        sym_cbc = SymmetricEncryption(mode="CBC")
        start_time = time.time()
        sym_cbc.encrypt(data)
        cbc_time = time.time() - start_time

        # Test GCM mode
        sym_gcm = SymmetricEncryption(mode="GCM")
        start_time = time.time()
        sym_gcm.encrypt(data)
        gcm_time = time.time() - start_time

        print(f"{size:11,d} | {ctr_time:.6f} | {cbc_time:.6f} | {gcm_time:.6f}")

    print("\nHashing Performance (hashing time in seconds):")
    print("Size (bytes) | MD5 | SHA-1 | SHA-256 | SHA-512 | BLAKE2b")
    print("-------------|-----|-------|---------|---------|--------")

    hasher = HashingFunctions()

    for size in data_sizes:
        data = os.urandom(size)

        # Test MD5
        start_time = time.time()
        hasher.md5(data)
        md5_time = time.time() - start_time

        # Test SHA-1
        start_time = time.time()
        hasher.sha1(data)
        sha1_time = time.time() - start_time

        # Test SHA-256
        start_time = time.time()
        hasher.sha256(data)
        sha256_time = time.time() - start_time

        # Test SHA-512
        start_time = time.time()
        hasher.sha512(data)
        sha512_time = time.time() - start_time

        # Test BLAKE2b
        start_time = time.time()
        hasher.blake2b(data)
        blake2b_time = time.time() - start_time

        print(f"{size:11,d} | {md5_time:.6f} | {sha1_time:.6f} | {sha256_time:.6f} | {sha512_time:.6f} | {blake2b_time:.6f}")


def main():
    """Main function to demonstrate the crypto_safety package with quick algorithms."""
    print("=== Crypto Safety Demonstration (Optimized for Speed) ===")
    print("This script demonstrates fast cryptographic operations while maintaining reasonable security.")

    try:
        # Run the demonstrations
        demonstrate_symmetric_encryption()
        demonstrate_asymmetric_encryption()
        demonstrate_hashing()
        secure_communication_example()
        demonstrate_fast_crypto()  # Add the fast crypto demonstration
        performance_comparison()

        print("\n=== All demonstrations completed successfully ===")
        print("Note: These implementations prioritize speed while maintaining reasonable security.")
        print("For high-security applications, consider using stronger parameters and algorithms.")

    except Exception as e:
        print(f"An error occurred: {str(e)}")


if __name__ == "__main__":
    main()