#!/usr/bin/env python3
"""
Crypto Safety CLI - Command-line interface for the Crypto Safety toolkit.

This module provides a command-line interface for the Crypto Safety toolkit,
allowing users to perform cryptographic operations from the command line.
"""

import argparse
import base64
import sys
import time
import os
from getpass import getpass

from crypto_safety.symmetric import SymmetricEncryption
from crypto_safety.asymmetric import AsymmetricEncryption
from crypto_safety.hash import HashingFunctions
from crypto_safety.fast_crypto import FastCrypto


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Crypto Safety - A fast cryptography toolkit'
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # Symmetric encryption
    sym_parser = subparsers.add_parser('symmetric', help='Symmetric encryption operations')
    sym_subparsers = sym_parser.add_subparsers(dest='sym_command', help='Symmetric command')

    # Generate key
    sym_keygen = sym_subparsers.add_parser('keygen', help='Generate a symmetric key')
    sym_keygen.add_argument('--mode', default='CTR', choices=['CTR', 'CBC', 'GCM'],
                            help='Encryption mode')
    sym_keygen.add_argument('--output', '-o', help='Output file for key')

    # Encrypt
    sym_encrypt = sym_subparsers.add_parser('encrypt', help='Encrypt data')
    sym_encrypt.add_argument('--key', '-k', required=True, help='Key file or base64 encoded key')
    sym_encrypt.add_argument('--input', '-i', help='Input file (stdin if not specified)')
    sym_encrypt.add_argument('--output', '-o', help='Output file (stdout if not specified)')
    sym_encrypt.add_argument('--mode', default='CTR', choices=['CTR', 'CBC', 'GCM'],
                            help='Encryption mode')

    # Decrypt
    sym_decrypt = sym_subparsers.add_parser('decrypt', help='Decrypt data')
    sym_decrypt.add_argument('--key', '-k', required=True, help='Key file or base64 encoded key')
    sym_decrypt.add_argument('--input', '-i', help='Input file (stdin if not specified)')
    sym_decrypt.add_argument('--output', '-o', help='Output file (stdout if not specified)')
    sym_decrypt.add_argument('--mode', default='CTR', choices=['CTR', 'CBC', 'GCM'],
                            help='Encryption mode')

    # Asymmetric encryption
    asym_parser = subparsers.add_parser('asymmetric', help='Asymmetric encryption operations')
    asym_subparsers = asym_parser.add_subparsers(dest='asym_command', help='Asymmetric command')

    # Generate keypair
    asym_keygen = asym_subparsers.add_parser('keygen', help='Generate an asymmetric keypair')
    asym_keygen.add_argument('--key-size', type=int, default=1024,
                            help='Key size in bits (default: 1024)')
    asym_keygen.add_argument('--private-key', '-p', required=True,
                            help='Output file for private key')
    asym_keygen.add_argument('--public-key', '-P', required=True,
                            help='Output file for public key')
    asym_keygen.add_argument('--password', action='store_true',
                            help='Encrypt private key with a password')

    # Encrypt
    asym_encrypt = asym_subparsers.add_parser('encrypt', help='Encrypt data with public key')
    asym_encrypt.add_argument('--key', '-k', required=True, help='Public key file')
    asym_encrypt.add_argument('--input', '-i', help='Input file (stdin if not specified)')
    asym_encrypt.add_argument('--output', '-o', help='Output file (stdout if not specified)')

    # Decrypt
    asym_decrypt = asym_subparsers.add_parser('decrypt', help='Decrypt data with private key')
    asym_decrypt.add_argument('--key', '-k', required=True, help='Private key file')
    asym_decrypt.add_argument('--input', '-i', help='Input file (stdin if not specified)')
    asym_decrypt.add_argument('--output', '-o', help='Output file (stdout if not specified)')
    asym_decrypt.add_argument('--password', action='store_true',
                             help='Private key is encrypted with a password')

    # Sign
    asym_sign = asym_subparsers.add_parser('sign', help='Sign data with private key')
    asym_sign.add_argument('--key', '-k', required=True, help='Private key file')
    asym_sign.add_argument('--input', '-i', help='Input file (stdin if not specified)')
    asym_sign.add_argument('--output', '-o', help='Output signature file (stdout if not specified)')
    asym_sign.add_argument('--password', action='store_true',
                          help='Private key is encrypted with a password')

    # Verify
    asym_verify = asym_subparsers.add_parser('verify', help='Verify signature with public key')
    asym_verify.add_argument('--key', '-k', required=True, help='Public key file')
    asym_verify.add_argument('--input', '-i', help='Input file (stdin if not specified)')
    asym_verify.add_argument('--signature', '-s', required=True, help='Signature file')

    # Hashing
    hash_parser = subparsers.add_parser('hash', help='Hashing operations')
    hash_subparsers = hash_parser.add_subparsers(dest='hash_command', help='Hash command')

    # Calculate hash
    hash_calc = hash_subparsers.add_parser('calculate', help='Calculate hash of data')
    hash_calc.add_argument('--algorithm', '-a', default='sha256',
                          choices=['md5', 'sha1', 'sha256', 'sha512', 'blake2b'],
                          help='Hash algorithm')
    hash_calc.add_argument('--input', '-i', help='Input file (stdin if not specified)')
    hash_calc.add_argument('--output', '-o', help='Output file (stdout if not specified)')

    # Password hashing
    hash_password = hash_subparsers.add_parser('password', help='Hash a password')
    hash_password.add_argument('--algorithm', '-a', default='pbkdf2',
                              choices=['pbkdf2', 'argon2'],
                              help='Password hashing algorithm')
    hash_password.add_argument('--iterations', type=int, default=10000,
                              help='Number of iterations for PBKDF2')
    hash_password.add_argument('--output', '-o', help='Output file (stdout if not specified)')

    # Verify password
    hash_verify = hash_subparsers.add_parser('verify', help='Verify a password hash')
    hash_verify.add_argument('--hash', '-H', required=True,
                            help='Password hash (file or string)')

    # Benchmark
    benchmark_parser = subparsers.add_parser('benchmark', help='Run benchmarks')
    benchmark_parser.add_argument('--iterations', type=int, default=100,
                                 help='Number of iterations for benchmarks')
    benchmark_parser.add_argument('--output', '-o', help='Output file (stdout if not specified)')

    return parser.parse_args()


def read_input(input_file):
    """Read input from a file or stdin."""
    if input_file:
        with open(input_file, 'rb') as f:
            return f.read()
    else:
        return sys.stdin.buffer.read()


def write_output(output_file, data, is_text=False):
    """Write output to a file or stdout."""
    if isinstance(data, str) and not is_text:
        data = data.encode('utf-8')
    elif isinstance(data, bytes) and is_text:
        data = data.decode('utf-8')

    if output_file:
        with open(output_file, 'wb' if isinstance(data, bytes) else 'w') as f:
            f.write(data)
    else:
        if isinstance(data, bytes):
            sys.stdout.buffer.write(data)
        else:
            sys.stdout.write(data)
        sys.stdout.write('\n')


def symmetric_commands(args):
    """Handle symmetric encryption commands."""
    if args.sym_command == 'keygen':
        sym = SymmetricEncryption(mode=args.mode)
        key_b64 = base64.b64encode(sym.key).decode('utf-8')
        write_output(args.output, key_b64, True)
        if not args.output:
            print("\nGenerated a new symmetric key with mode:", args.mode)

    elif args.sym_command == 'encrypt':
        # Load key
        if os.path.isfile(args.key):
            with open(args.key, 'r') as f:
                key = base64.b64decode(f.read().strip())
        else:
            key = base64.b64decode(args.key)

        sym = SymmetricEncryption(key=key, mode=args.mode)
        data = read_input(args.input)
        if isinstance(data, bytes):
            encrypted = sym.encrypt(data)
        else:
            encrypted = sym.encrypt(data.decode('utf-8'))
        write_output(args.output, encrypted, True)

    elif args.sym_command == 'decrypt':
        # Load key
        if os.path.isfile(args.key):
            with open(args.key, 'r') as f:
                key = base64.b64decode(f.read().strip())
        else:
            key = base64.b64decode(args.key)

        sym = SymmetricEncryption(key=key, mode=args.mode)
        data = read_input(args.input)
        if isinstance(data, str):
            data = data.encode('utf-8')
        decrypted = sym.decrypt(data)
        write_output(args.output, decrypted)

    else:
        print("Unknown symmetric command:", args.sym_command)
        return 1

    return 0


def asymmetric_commands(args):
    """Handle asymmetric encryption commands."""
    if args.asym_command == 'keygen':
        asym = AsymmetricEncryption(key_size=args.key_size)

        # Export private key
        password = None
        if args.password:
            password = getpass("Enter password to encrypt private key: ")
            password_confirm = getpass("Confirm password: ")
            if password != password_confirm:
                print("Passwords do not match")
                return 1

        private_key = asym.export_private_key(password)
        with open(args.private_key, 'w') as f:
            f.write(private_key)

        # Export public key
        public_key = asym.export_public_key()
        with open(args.public_key, 'w') as f:
            f.write(public_key)

        print(f"Generated {args.key_size}-bit RSA keypair")
        print(f"Private key saved to: {args.private_key}")
        print(f"Public key saved to: {args.public_key}")

    elif args.asym_command == 'encrypt':
        # Load public key
        with open(args.key, 'r') as f:
            public_key = f.read()

        asym = AsymmetricEncryption.from_public_key_pem(public_key)
        data = read_input(args.input)
        if isinstance(data, bytes):
            encrypted = asym.encrypt(data)
        else:
            encrypted = asym.encrypt(data.decode('utf-8'))
        write_output(args.output, encrypted, True)

    elif args.asym_command == 'decrypt':
        # Load private key
        with open(args.key, 'r') as f:
            private_key = f.read()

        password = None
        if args.password:
            password = getpass("Enter private key password: ")

        asym = AsymmetricEncryption.from_private_key_pem(private_key, password)
        data = read_input(args.input)
        if isinstance(data, str):
            data = data.encode('utf-8')
        decrypted = asym.decrypt(data)
        write_output(args.output, decrypted)

    elif args.asym_command == 'sign':
        # Load private key
        with open(args.key, 'r') as f:
            private_key = f.read()

        password = None
        if args.password:
            password = getpass("Enter private key password: ")

        asym = AsymmetricEncryption.from_private_key_pem(private_key, password)
        data = read_input(args.input)
        if isinstance(data, bytes):
            signature = asym.sign(data)
        else:
            signature = asym.sign(data.decode('utf-8'))
        write_output(args.output, signature, True)

    elif args.asym_command == 'verify':
        # Load public key
        with open(args.key, 'r') as f:
            public_key = f.read()

        # Load signature
        with open(args.signature, 'r') as f:
            signature = f.read().strip()

        asym = AsymmetricEncryption.from_public_key_pem(public_key)
        data = read_input(args.input)
        if isinstance(data, bytes):
            is_valid = asym.verify(data, signature)
        else:
            is_valid = asym.verify(data.decode('utf-8'), signature)

        result = "Signature is valid" if is_valid else "Signature is invalid"
        print(result)
        return 0 if is_valid else 1

    else:
        print("Unknown asymmetric command:", args.asym_command)
        return 1

    return 0


def hash_commands(args):
    """Handle hashing commands."""
    hasher = HashingFunctions()

    if args.hash_command == 'calculate':
        data = read_input(args.input)
        if isinstance(data, str):
            data = data.encode('utf-8')

        if args.algorithm == 'md5':
            hash_value = hasher.md5(data)
        elif args.algorithm == 'sha1':
            hash_value = hasher.sha1(data)
        elif args.algorithm == 'sha256':
            hash_value = hasher.sha256(data)
        elif args.algorithm == 'sha512':
            hash_value = hasher.sha512(data)
        elif args.algorithm == 'blake2b':
            hash_value = hasher.blake2b(data)
        else:
            print("Unknown hash algorithm:", args.algorithm)
            return 1

        write_output(args.output, hash_value, True)

    elif args.hash_command == 'password':
        password = getpass("Enter password to hash: ")

        if args.algorithm == 'pbkdf2':
            hashed = hasher.pbkdf2_hash_password(
                password,
                iterations=args.iterations,
                hash_name='sha1'
            )
        elif args.algorithm == 'argon2':
            hashed = hasher.argon2_hash_password(password)
        else:
            print("Unknown password hashing algorithm:", args.algorithm)
            return 1

        write_output(args.output, hashed, True)

    elif args.hash_command == 'verify':
        password = getpass("Enter password to verify: ")

        # Check if the hash is in a file
        if os.path.isfile(args.hash):
            with open(args.hash, 'r') as f:
                stored_hash = f.read().strip()
        else:
            stored_hash = args.hash

        # Detect hash type
        if stored_hash.startswith('$argon2'):
            is_valid = hasher.verify_argon2_password(password, stored_hash)
        else:
            is_valid = hasher.verify_pbkdf2_password(password, stored_hash)

        result = "Password is valid" if is_valid else "Password is invalid"
        print(result)
        return 0 if is_valid else 1

    else:
        print("Unknown hash command:", args.hash_command)
        return 1

    return 0


def run_benchmarks(args):
    """Run benchmarks."""
    fast = FastCrypto()

    print("Running benchmarks...")
    start_time = time.time()

    results = fast.benchmark(iterations=args.iterations)

    duration = time.time() - start_time

    # Format results
    output = [
        "Crypto Safety Benchmarks",
        "=======================",
        f"Iterations: {args.iterations}",
        f"Total duration: {duration:.2f} seconds",
        "",
        "Symmetric Encryption:",
        f"  AES-128-CTR: {results['aes_ctr_encrypt']['mb_per_second']:.2f} MB/s",
        "",
        "Hashing:",
        f"  MD5: {results['md5_hash']['mb_per_second']:.2f} MB/s",
        f"  SHA-1: {results['sha1_hash']['mb_per_second']:.2f} MB/s",
        f"  SHA-256: {results['sha256_hash']['mb_per_second']:.2f} MB/s",
        f"  BLAKE2b: {results['blake2b_hash']['mb_per_second']:.2f} MB/s",
        "",
        "Password Hashing:",
        f"  PBKDF2 (10,000 iterations): {results['pbkdf2_hash']['operations_per_second']:.2f} op/s",
        "",
        "RSA Operations (1024-bit):",
        f"  Key generation: {results['rsa_keygen']['operations_per_second']:.2f} op/s",
        f"  Encryption: {results['rsa_encrypt']['operations_per_second']:.2f} op/s",
        f"  Decryption: {results['rsa_decrypt']['operations_per_second']:.2f} op/s",
        f"  Signing: {results['rsa_sign']['operations_per_second']:.2f} op/s",
        f"  Verification: {results['rsa_verify']['operations_per_second']:.2f} op/s",
    ]

    output_str = "\n".join(output)
    write_output(args.output, output_str, True)

    return 0


def main():
    """Main entry point."""
    args = parse_args()

    if args.command == 'symmetric':
        return symmetric_commands(args)
    elif args.command == 'asymmetric':
        return asymmetric_commands(args)
    elif args.command == 'hash':
        return hash_commands(args)
    elif args.command == 'benchmark':
        return run_benchmarks(args)
    else:
        print("Please specify a command. Use --help for more information.")
        return 1


if __name__ == '__main__':
    sys.exit(main())
