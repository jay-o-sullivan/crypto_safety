#!/usr/bin/env python3
"""
Build script for creating distributable packages of Crypto Safety.
"""

import os
import shutil
import subprocess
import sys

def clean_previous_builds():
    """Clean previous build artifacts."""
    print("Cleaning previous build artifacts...")
    directories_to_clean = ['build', 'dist', 'crypto_safety.egg-info']
    for directory in directories_to_clean:
        if os.path.exists(directory):
            shutil.rmtree(directory)
            print(f"  Removed {directory}")

def build_package():
    """Build the Python package."""
    print("\nBuilding package...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "build"])
        subprocess.check_call([sys.executable, "-m", "build"])
        print("  Package built successfully!")
    except subprocess.CalledProcessError as e:
        print(f"  Error building package: {e}")
        return False
    return True

def show_distribution_files():
    """Show the distribution files created."""
    print("\nDistribution files created:")
    if os.path.exists('dist'):
        for file in os.listdir('dist'):
            file_path = os.path.join('dist', file)
            size = os.path.getsize(file_path) / 1024  # Convert to KB
            print(f"  {file} ({size:.1f} KB)")

def show_next_steps():
    """Show next steps for publishing."""
    print("\nNext steps:")
    print("  1. Test the package locally:")
    print("     pip install -e .")
    print("\n  2. Upload to PyPI (when ready):")
    print("     python -m pip install --upgrade twine")
    print("     python -m twine upload dist/*")
    print("\n  3. Install from PyPI:")
    print("     pip install crypto-safety")

def main():
    """Main function."""
    clean_previous_builds()
    if build_package():
        show_distribution_files()
        show_next_steps()

if __name__ == '__main__':
    main()
