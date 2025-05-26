from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="crypto-safety",
    version="0.1.0",
    author="Jay O'Sullivan",
    author_email="your.email@example.com",
    description="A lightweight and fast Python cryptography toolkit",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/jay-o-sullivan/crypto_safety",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography",
        "Intended Audience :: Developers",
    ],
    python_requires=">=3.6",
    install_requires=[
        "cryptography>=41.0.1",
        "pycryptodome>=3.18.0",
        "pyca>=0.6.0",
    ],
    extras_require={
        "argon2": ["argon2-cffi>=21.3.0"],
    },
    entry_points={
        "console_scripts": [
            "crypto-safety=crypto_safety.cli:main",
        ],
    },
)
