# GitHub Repository Summary: Crypto Safety

## Repository Information
- **Name**: crypto_safety
- **URL**: https://github.com/jay-o-sullivan/crypto_safety
- **Description**: A lightweight and fast Python cryptography toolkit that prioritizes speed while maintaining reasonable security

## Key Features
1. **Optimized Cryptographic Implementations**
   - Symmetric encryption using AES-128-CTR (up to 2x faster than standard implementations)
   - Fast asymmetric encryption with 1024-bit RSA (4x faster key generation)
   - Fast hashing functions (MD5, SHA-1, SHA-256, BLAKE2b)
   - Performance-optimized password hashing

2. **Speed-Focused Design**
   - Careful parameter selection for maximum performance
   - Reduced security parameters where reasonable
   - Specialized fast crypto module for performance-critical applications
   - Comprehensive benchmarking capabilities

3. **Well-Documented API**
   - Clear examples for all cryptographic operations
   - Performance comparison tables
   - Security considerations and recommendations

## Project Structure
- **asymmetric.py**: Fast RSA implementation with 1024-bit keys
- **symmetric.py**: Optimized AES encryption with CTR, CBC, and GCM modes
- **hash.py**: Optimized hashing functions and password hashing
- **fast_crypto.py**: Ultra-fast implementations for maximum performance
- **main.py**: Demonstrations and benchmarks
- **README.md**: Documentation and usage examples
- **requirements.txt**: Dependencies

## Key Optimizations
1. **Symmetric Encryption**:
   - Using AES-128 instead of AES-256 (1.4x faster)
   - Added CTR mode (fastest and parallelizable)
   - Reduced key size from 32 bytes to 16 bytes

2. **Asymmetric Encryption**:
   - Reduced RSA key size from 2048 to 1024 bits (4x faster)
   - Using SHA-1 instead of SHA-256 for RSA operations
   - Using PKCS1v15 padding instead of PSS (faster)

3. **Hashing Functions**:
   - Added MD5 for non-security-critical checksums (fastest)
   - Added SHA-1 for speed-critical operations
   - Optimized BLAKE2b implementation

4. **Password Hashing**:
   - Reduced PBKDF2 iterations from 100,000 to 10,000
   - Using SHA-1 for PBKDF2 hashing
   - Reduced output key length for better performance
   - Optimized Argon2 parameters

5. **Fast Crypto Module**:
   - Ultra-optimized AES-CTR implementation
   - Specialized fast hashing functions
   - Built-in performance benchmarking

## Performance Results
| Operation | Standard Implementation | Optimized Implementation | Speed Improvement |
|-----------|-------------------------|--------------------------|-------------------|
| AES Encryption | 145 MB/s (AES-256-GCM) | 290 MB/s (AES-128-CTR) | 2.0x |
| RSA Key Gen | 1.2 sec (2048-bit) | 0.3 sec (1024-bit) | 4.0x |
| RSA Encrypt | 5.2 ms (2048-bit) | 1.8 ms (1024-bit) | 2.9x |
| Password Hash | 1.2 sec (PBKDF2-100K) | 0.12 sec (PBKDF2-10K) | 10.0x |
| Hash Function | 220 MB/s (SHA-256) | 560 MB/s (SHA-1) | 2.5x |

## Security Considerations
This library prioritizes performance over maximum security. For applications requiring the highest level of security, it recommends:
- Using AES-256 instead of AES-128
- Using 2048 or 4096-bit RSA keys
- Using SHA-256 or SHA-512 instead of SHA-1
- Increasing PBKDF2 iterations to 100,000+
- Using Argon2id with higher memory and time parameters
