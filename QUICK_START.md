# Crypto Safety Quick Start Guide

This quick start guide will help you get started with the Crypto Safety toolkit.

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/jay-o-sullivan/crypto_safety.git
cd crypto_safety

# Install the package
pip install -e .
```

## Using as a Python Library

The Crypto Safety toolkit can be used as a Python library in your own projects:

```python
# Import the components you need
from crypto_safety import SymmetricEncryption, AsymmetricEncryption, HashingFunctions, FastCrypto

# Example: Symmetric encryption
symmetric = SymmetricEncryption(mode="CTR")
encrypted = symmetric.encrypt("Secret message")
decrypted = symmetric.decrypt(encrypted)

# Example: Fast hashing
hasher = HashingFunctions()
hash_value = hasher.sha1("Data to hash")
```

## Running the Examples

The toolkit includes example scripts that demonstrate its features:

```bash
# Run the examples script
python examples.py
```

## Running Benchmarks

To benchmark the performance of the toolkit:

```bash
# Run the examples script (includes benchmarks)
python examples.py
```

## Standalone Usage

If you encounter issues with the dependencies, you can use the standalone scripts:

```bash
# Run the standalone demo
python standalone_demo.py

# Run the standalone examples with all features
python standalone_examples.py --all

# Run specific standalone examples
python standalone_examples.py --symmetric  # Symmetric encryption
python standalone_examples.py --hash       # Hashing functions
python standalone_examples.py --rsa        # RSA encryption
python standalone_examples.py --benchmark  # Performance benchmarks
```

## Simple CLI Tool

The toolkit also includes a simple command-line interface:

```bash
# Show version information
python crypto_safety_simple_cli.py --version

# Run a demonstration
python crypto_safety_simple_cli.py --demo

# Run benchmarks
python crypto_safety_simple_cli.py --benchmark
```

## Building a Distribution Package

To build a distribution package for sharing or uploading to PyPI:

```bash
# Run the build script
python build_package.py
```

This will create both a source distribution (.tar.gz) and a wheel (.whl) in the `dist` directory.

## Project Structure

- `crypto_safety/`: Main package directory
  - `__init__.py`: Package initialization
  - `symmetric.py`: Symmetric encryption (AES)
  - `asymmetric.py`: Asymmetric encryption (RSA)
  - `hash.py`: Hashing functions
  - `fast_crypto.py`: Ultra-fast implementations
  - `cli.py`: Command-line interface

- `examples.py`: Example usage and benchmarks
- `build_package.py`: Script to build distribution packages
- `test_package.py`: Script to test the installed package

## Key Features

- **Fast AES-128-CTR Encryption**: Optimized for speed
- **Fast 1024-bit RSA**: 4x faster than standard implementations
- **Fast Hashing**: Optimized MD5, SHA-1, SHA-256
- **Password Hashing**: Fast PBKDF2 and Argon2
- **Benchmarking**: Built-in performance measurement tools

## Security Notice

This toolkit prioritizes speed over maximum security. For applications requiring the highest security level, consider using stronger parameters as documented in the README.
