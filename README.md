# Crypto Safety

A lightweight and fast Python cryptography toolkit that implements common cryptographic operations with a focus on speed and reasonable security.

## Features

- **Symmetric Encryption**: Fast AES encryption with CTR, CBC, and GCM modes
- **Asymmetric Encryption**: RSA encryption, decryption, signing, and verification
- **Hashing Functions**: MD5, SHA-1, SHA-256, SHA-512, and BLAKE2b
- **Password Hashing**: PBKDF2 and Argon2 (optional)
- **HMAC**: Message authentication with various hash algorithms
- **Fast Crypto**: Ultra-fast implementations for performance-critical applications
- **Performance Benchmarks**: Compare speed of different algorithms

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Symmetric Encryption (Fast AES-128-CTR)

```python
from symmetric import SymmetricEncryption

# Create a symmetric encryption object with a generated key using CTR mode (fastest)
symmetric = SymmetricEncryption(mode="CTR")

# Encrypt some data
message = "This is a secret message."
encrypted_data = symmetric.encrypt(message)

# Decrypt the data
decrypted_data = symmetric.decrypt(encrypted_data)
print(decrypted_data.decode('utf-8'))  # "This is a secret message."
```

### Asymmetric Encryption (Fast 1024-bit RSA)

```python
from asymmetric import AsymmetricEncryption

# Create an asymmetric encryption object with a smaller key for better performance
asymmetric = AsymmetricEncryption(key_size=1024)

# Encrypt a message with the public key
message = "This message is encrypted with RSA."
encrypted_data = asymmetric.encrypt(message)

# Decrypt the message with the private key
decrypted_data = asymmetric.decrypt(encrypted_data)
print(decrypted_data.decode('utf-8'))  # "This message is encrypted with RSA."

# Create a digital signature
document = "This document needs to be signed."
signature = asymmetric.sign(document)

# Verify the signature
is_valid = asymmetric.verify(document, signature)
print(is_valid)  # True
```

### Fast Hashing

```python
from hash import HashingFunctions

hasher = HashingFunctions()

# Use various hash functions (from fastest to slowest)
message = "Hash this message."

# MD5 (fastest but less secure)
md5_hash = hasher.md5(message)

# SHA-1 (fast with reasonable security)
sha1_hash = hasher.sha1(message)

# SHA-256 (good balance of security and speed)
sha256_hash = hasher.sha256(message)

# BLAKE2b (fast with high security)
blake2b_hash = hasher.blake2b(message)

# SHA-512 (most secure but slower)
sha512_hash = hasher.sha512(message)
```

### Fast Password Hashing

```python
from hash import HashingFunctions

hasher = HashingFunctions()

# Hash a password with PBKDF2 (optimized for speed)
password = "secure_password123"
hashed_password = hasher.pbkdf2_hash_password(
    password,
    iterations=10000,  # Lower for better performance
    hash_name='sha1'   # Faster than SHA-256
)

# Verify the password
is_valid = hasher.verify_pbkdf2_password(password, hashed_password)
print(is_valid)  # True
```

### Ultra-Fast Crypto (for performance-critical applications)

```python
from fast_crypto import FastCrypto

fast = FastCrypto()

# Fast encryption with AES-128-CTR
message = "Need for speed!"
encrypted = fast.aes_ctr_encrypt(message)

# Fast decryption
decrypted = fast.aes_ctr_decrypt(encrypted)
print(decrypted.decode('utf-8'))  # "Need for speed!"

# Fast hashing
md5_hash = fast.fast_hash(message, algorithm='md5')  # Fastest
sha1_hash = fast.fast_hash(message, algorithm='sha1')  # Fast with reasonable security

# Benchmark operations
benchmark_results = fast.benchmark()
print(f"AES-CTR Encryption: {benchmark_results['aes_ctr_encrypt']['mb_per_second']:.2f} MB/sec")
```

## Performance Considerations

This library is optimized for speed while maintaining reasonable security:

- Uses AES-128 instead of AES-256 for symmetric encryption
- Uses CTR mode which is faster and parallelizable
- Uses 1024-bit RSA keys instead of 2048-bit or larger
- Uses SHA-1 for HMACs and signatures where appropriate
- Reduces PBKDF2 iterations for password hashing
- Provides MD5 for non-security-critical checksums

For high-security applications, consider using stronger parameters and algorithms.

## Running the Demo

```bash
python main.py
```

The demo script demonstrates all cryptographic operations and includes performance benchmarks.

## Requirements

- cryptography>=41.0.1
- pycryptodome>=3.18.0
- pyca>=0.6.0
- argon2-cffi>=21.3.0 (optional, for Argon2 password hashing)