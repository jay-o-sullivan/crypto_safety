# Crypto Safety Tool Guide

This guide explains how to use the Crypto Safety tool for fast cryptographic operations.

## Installation Options

### Option 1: Install from PyPI (once published)

```bash
pip install crypto-safety
```

After installation, you can use the tool with the `crypto-safety` command.

### Option 2: Install from GitHub

```bash
git clone https://github.com/jay-o-sullivan/crypto_safety.git
cd crypto_safety
pip install -e .
```

### Option 3: Use as a Python library

```python
from crypto_safety import SymmetricEncryption, AsymmetricEncryption, HashingFunctions, FastCrypto
```

## Command-line Tool Usage

The Crypto Safety tool provides a comprehensive command-line interface for all cryptographic operations.

### Symmetric Encryption

#### Generate a new symmetric key

```bash
crypto-safety symmetric keygen --mode CTR --output my.key
```

Available modes: `CTR` (fastest), `CBC`, `GCM` (most secure)

#### Encrypt a file

```bash
crypto-safety symmetric encrypt --key my.key --input plaintext.txt --output encrypted.txt
```

#### Encrypt text from stdin

```bash
echo "Secret message" | crypto-safety symmetric encrypt --key my.key > encrypted.txt
```

#### Decrypt a file

```bash
crypto-safety symmetric decrypt --key my.key --input encrypted.txt --output decrypted.txt
```

### Asymmetric Encryption (RSA)

#### Generate a keypair

```bash
# Without password protection
crypto-safety asymmetric keygen --private-key private.pem --public-key public.pem

# With password protection
crypto-safety asymmetric keygen --private-key private.pem --public-key public.pem --password
```

#### Encrypt with public key

```bash
crypto-safety asymmetric encrypt --key public.pem --input plaintext.txt --output encrypted.txt
```

#### Decrypt with private key

```bash
# Without password
crypto-safety asymmetric decrypt --key private.pem --input encrypted.txt --output decrypted.txt

# With password
crypto-safety asymmetric decrypt --key private.pem --input encrypted.txt --output decrypted.txt --password
```

#### Sign a file

```bash
crypto-safety asymmetric sign --key private.pem --input document.txt --output signature.txt
```

#### Verify a signature

```bash
crypto-safety asymmetric verify --key public.pem --input document.txt --signature signature.txt
```

### Hashing

#### Calculate hash of a file

```bash
crypto-safety hash calculate --algorithm sha256 --input file.txt
```

Available algorithms: `md5` (fastest), `sha1` (fast), `sha256`, `sha512`, `blake2b`

#### Hash a password

```bash
crypto-safety hash password --algorithm pbkdf2 --output hashed_password.txt
```

Available algorithms: `pbkdf2` (faster), `argon2` (more secure)

#### Verify a password

```bash
crypto-safety hash verify --hash hashed_password.txt
```

### Benchmarks

#### Run performance benchmarks

```bash
crypto-safety benchmark --iterations 100
```

## Python Library Usage

### Symmetric Encryption

```python
from crypto_safety import SymmetricEncryption

# Create a new encryption object with CTR mode (fastest)
sym = SymmetricEncryption(mode="CTR")

# Encrypt data
encrypted = sym.encrypt("Secret message")

# Decrypt data
decrypted = sym.decrypt(encrypted)
print(decrypted.decode('utf-8'))  # "Secret message"
```

### Asymmetric Encryption

```python
from crypto_safety import AsymmetricEncryption

# Generate a new keypair
asym = AsymmetricEncryption(key_size=1024)

# Export keys
private_key = asym.export_private_key()
public_key = asym.export_public_key()

# Create an encryption object from a public key (encryption only)
encryptor = AsymmetricEncryption.from_public_key_pem(public_key)
encrypted = encryptor.encrypt("Secret message")

# Create a decryption object from a private key
decryptor = AsymmetricEncryption.from_private_key_pem(private_key)
decrypted = decryptor.decrypt(encrypted)
print(decrypted.decode('utf-8'))  # "Secret message"

# Signing and verification
signature = decryptor.sign("Document to sign")
is_valid = encryptor.verify("Document to sign", signature)
print(is_valid)  # True
```

### Fast Crypto Module

```python
from crypto_safety import FastCrypto

fast = FastCrypto()

# Run benchmarks
results = fast.benchmark()
print(f"AES-CTR: {results['aes_ctr_encrypt']['mb_per_second']:.2f} MB/s")
print(f"MD5: {results['md5_hash']['mb_per_second']:.2f} MB/s")
print(f"SHA-1: {results['sha1_hash']['mb_per_second']:.2f} MB/s")
```

## Security Considerations

This tool prioritizes performance over maximum security. For applications requiring the highest level of security, consider:

- Using AES-256 instead of AES-128
- Using 2048 or 4096-bit RSA keys
- Using SHA-256 or SHA-512 instead of SHA-1
- Increasing PBKDF2 iterations to 100,000+
- Using Argon2id with higher memory and time parameters

## Publishing to PyPI

To publish the package to PyPI:

```bash
# Build the package
python -m pip install --upgrade build
python -m build

# Upload to PyPI
python -m pip install --upgrade twine
python -m twine upload dist/*
```
