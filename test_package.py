#!/usr/bin/env python3
"""
Test script for the Crypto Safety package.
Verifies that the package is properly installed and working.
"""

import sys
import base64

def test_symmetric():
    """Test symmetric encryption functionality."""
    print("Testing symmetric encryption...")

    try:
        from crypto_safety import SymmetricEncryption

        # Create a new encryption object
        symmetric = SymmetricEncryption(mode="CTR")

        # Test encryption and decryption
        plaintext = "This is a test message for symmetric encryption."
        encrypted = symmetric.encrypt(plaintext)
        decrypted = symmetric.decrypt(encrypted)

        if decrypted.decode('utf-8') == plaintext:
            print("  ✓ Symmetric encryption/decryption successful")
        else:
            print("  ✗ Symmetric decryption failed")
            return False

        # Test key export/import
        key_b64 = base64.b64encode(symmetric.key).decode('utf-8')
        symmetric2 = SymmetricEncryption(key=base64.b64decode(key_b64), mode="CTR")
        encrypted2 = symmetric2.encrypt(plaintext)
        decrypted2 = symmetric.decrypt(encrypted2)

        if decrypted2.decode('utf-8') == plaintext:
            print("  ✓ Key export/import successful")
        else:
            print("  ✗ Key export/import failed")
            return False

    except Exception as e:
        print(f"  ✗ Symmetric encryption test failed: {e}")
        return False

    return True

def test_asymmetric():
    """Test asymmetric encryption functionality."""
    print("\nTesting asymmetric encryption...")

    try:
        from crypto_safety import AsymmetricEncryption

        # Create a new keypair
        asymmetric = AsymmetricEncryption(key_size=1024)

        # Test encryption and decryption
        plaintext = "This is a test message for asymmetric encryption."
        encrypted = asymmetric.encrypt(plaintext)
        decrypted = asymmetric.decrypt(encrypted)

        if decrypted.decode('utf-8') == plaintext:
            print("  ✓ Asymmetric encryption/decryption successful")
        else:
            print("  ✗ Asymmetric decryption failed")
            return False

        # Test signing and verification
        document = "This is a test document to be signed."
        signature = asymmetric.sign(document)
        is_valid = asymmetric.verify(document, signature)

        if is_valid:
            print("  ✓ Signature verification successful")
        else:
            print("  ✗ Signature verification failed")
            return False

        # Test key export/import
        private_key = asymmetric.export_private_key()
        public_key = asymmetric.export_public_key()

        asymmetric2 = AsymmetricEncryption.from_private_key_pem(private_key)
        encrypted2 = asymmetric2.encrypt(plaintext)
        decrypted2 = asymmetric2.decrypt(encrypted2)

        if decrypted2.decode('utf-8') == plaintext:
            print("  ✓ Key export/import successful")
        else:
            print("  ✗ Key export/import failed")
            return False

    except Exception as e:
        print(f"  ✗ Asymmetric encryption test failed: {e}")
        return False

    return True

def test_hashing():
    """Test hashing functionality."""
    print("\nTesting hashing functions...")

    try:
        from crypto_safety import HashingFunctions

        hasher = HashingFunctions()

        # Test various hash functions
        message = "This is a test message for hashing."

        md5_hash = hasher.md5(message)
        sha1_hash = hasher.sha1(message)
        sha256_hash = hasher.sha256(message)
        blake2b_hash = hasher.blake2b(message)

        if all([md5_hash, sha1_hash, sha256_hash, blake2b_hash]):
            print("  ✓ Hash functions successful")
        else:
            print("  ✗ Hash functions failed")
            return False

        # Test password hashing
        password = "test_password123"
        hashed = hasher.pbkdf2_hash_password(password, iterations=1000)
        is_valid = hasher.verify_pbkdf2_password(password, hashed)

        if is_valid:
            print("  ✓ Password hashing successful")
        else:
            print("  ✗ Password hashing failed")
            return False

    except Exception as e:
        print(f"  ✗ Hashing test failed: {e}")
        return False

    return True

def test_fast_crypto():
    """Test fast crypto functionality."""
    print("\nTesting fast crypto module...")

    try:
        from crypto_safety import FastCrypto

        fast = FastCrypto()

        # Test fast encryption
        message = "This is a test message for fast encryption."
        encrypted = fast.aes_ctr_encrypt(message)
        decrypted = fast.aes_ctr_decrypt(encrypted)

        if decrypted.decode('utf-8') == message:
            print("  ✓ Fast encryption successful")
        else:
            print("  ✗ Fast encryption failed")
            return False

        # Test fast hashing
        md5_hash = fast.fast_hash(message, algorithm='md5')
        sha1_hash = fast.fast_hash(message, algorithm='sha1')

        if md5_hash and sha1_hash:
            print("  ✓ Fast hashing successful")
        else:
            print("  ✗ Fast hashing failed")
            return False

        # Test benchmarking
        benchmark_results = fast.benchmark(iterations=1)

        if benchmark_results and 'aes_ctr_encrypt' in benchmark_results:
            print("  ✓ Benchmarking successful")
        else:
            print("  ✗ Benchmarking failed")
            return False

    except Exception as e:
        print(f"  ✗ Fast crypto test failed: {e}")
        return False

    return True

def main():
    """Main function."""
    print("Crypto Safety Package Test\n" + "="*25)

    # Test import
    try:
        import crypto_safety
        print(f"Package version: {crypto_safety.__version__}")
    except ImportError:
        print("Failed to import crypto_safety package. Is it installed?")
        return 1

    # Run tests
    tests = [
        test_symmetric,
        test_asymmetric,
        test_hashing,
        test_fast_crypto
    ]

    results = [test() for test in tests]

    # Summary
    print("\nTest Summary:")
    print(f"  Passed: {results.count(True)}/{len(results)}")
    print(f"  Failed: {results.count(False)}/{len(results)}")

    return 0 if all(results) else 1

if __name__ == '__main__':
    sys.exit(main())
