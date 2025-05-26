#!/usr/bin/env python3
"""
Crypto Safety command-line tool wrapper.
This script provides a simple interface to the crypto_safety package.
"""

import argparse
import sys
import os
import subprocess

def main():
    """Main entry point for the crypto_safety command-line tool."""
    parser = argparse.ArgumentParser(
        description='Crypto Safety - A fast cryptography toolkit'
    )

    # Command categories
    parser.add_argument('--version', action='store_true', help='Show version information')
    parser.add_argument('--benchmark', action='store_true', help='Run benchmarks')
    parser.add_argument('--demo', action='store_true', help='Run a demonstration')

    args = parser.parse_args()

    if args.version:
        print("Crypto Safety v0.1.0")
        print("A lightweight and fast Python cryptography toolkit")
        print("https://github.com/jay-o-sullivan/crypto_safety")
        return 0

    if args.benchmark:
        # Run the benchmark script
        print("Running benchmarks...")
        try:
            # Get the directory of this script
            script_dir = os.path.dirname(os.path.abspath(__file__))
            benchmark_script = os.path.join(script_dir, "examples.py")
            subprocess.run([sys.executable, benchmark_script])
            return 0
        except Exception as e:
            print(f"Error running benchmarks: {e}")
            return 1

    if args.demo:
        # Run the demo script
        print("Running demonstration...")
        try:
            # Get the directory of this script
            script_dir = os.path.dirname(os.path.abspath(__file__))
            demo_script = os.path.join(script_dir, "examples.py")
            subprocess.run([sys.executable, demo_script])
            return 0
        except Exception as e:
            print(f"Error running demonstration: {e}")
            return 1

    # If no arguments are provided, show help
    parser.print_help()
    return 0

if __name__ == '__main__':
    sys.exit(main())
