# Crypto Safety - Update and Known Issues

## Known Issues

There is a known issue with the `cryptography` library on some Windows systems that can cause the following error:

```
ImportError: DLL load failed while importing _rust: The specified procedure could not be found.
```

This occurs when running the full Crypto Safety package that depends on the cryptography library.

## Workarounds

### 1. Use the Standalone Demo and Examples

We have provided standalone versions of the key functionality that don't depend on external cryptography libraries:

- `standalone_demo.py` - A simple demo of the core functionality
- `standalone_examples.py` - More comprehensive examples with benchmarks

These scripts provide most of the functionality of the main package without the dependency issues.

To run the standalone examples:

```bash
python standalone_examples.py --all  # Run all examples
python standalone_examples.py --symmetric  # Run only symmetric encryption example
python standalone_examples.py --hash  # Run only hashing example
python standalone_examples.py --rsa  # Run only RSA example
python standalone_examples.py --benchmark  # Run benchmarks
```

### 2. Use the Simple CLI

The `crypto_safety_simple_cli.py` script provides a command-line interface that doesn't depend on the cryptography library:

```bash
python crypto_safety_simple_cli.py --version  # Show version information
python crypto_safety_simple_cli.py --demo  # Run a demonstration
python crypto_safety_simple_cli.py --benchmark  # Run benchmarks
```

## Future Plans

1. Fix the dependency issues with the cryptography library
2. Provide a pure Python implementation of the core functionality
3. Add more standalone examples and demos
4. Publish the package to PyPI

## Need Help?

If you encounter any issues, please:
1. Check the QUICK_START.md and TOOL_GUIDE.md files for more information
2. Use the standalone scripts as a workaround
3. Open an issue on GitHub
