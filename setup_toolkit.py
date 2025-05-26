#!/usr/bin/env python3
"""
Setup script for the Crypto Safety toolkit.
This script installs the package and its dependencies.
"""

import subprocess
import sys
import os
import platform

def main():
    """Main setup function."""
    print("Setting up Crypto Safety toolkit...")

    # Check Python version
    python_version = platform.python_version()
    print(f"Python version: {python_version}")

    # Install dependencies
    print("\nInstalling dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("Dependencies installed successfully.")
    except subprocess.CalledProcessError:
        print("Error installing dependencies.")
        return 1

    # Install the package in development mode
    print("\nInstalling Crypto Safety package...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-e", "."])
        print("Package installed successfully.")
    except subprocess.CalledProcessError:
        print("Error installing package.")
        return 1

    # Print success message
    print("\nSetup complete!")
    print("You can now use the Crypto Safety toolkit:")
    print("  - Import in Python: from crypto_safety import SymmetricEncryption")
    print("  - Run examples: python examples.py")
    print("  - Run benchmarks: python examples.py")
    print("  - Build package: python build_package.py")

    return 0

if __name__ == "__main__":
    sys.exit(main())
