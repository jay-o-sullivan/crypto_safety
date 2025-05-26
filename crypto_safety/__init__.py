"""
Crypto Safety - A lightweight and fast Python cryptography toolkit.

This package provides optimized cryptographic operations with a focus on speed
while maintaining reasonable security.
"""

__version__ = '0.1.0'

from .symmetric import SymmetricEncryption
from .asymmetric import AsymmetricEncryption
from .hash import HashingFunctions
from .fast_crypto import FastCrypto

__all__ = ['SymmetricEncryption', 'AsymmetricEncryption', 'HashingFunctions', 'FastCrypto']
