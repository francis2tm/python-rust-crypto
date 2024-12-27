#!/bin/bash

# Cleanup any existing files
cleanup() {
    rm -f python_key.pub rust_key.pub encrypted.bin
}

# Cleanup at start
cleanup

# Run Rust program first to generate its public key
echo "Generating Rust public key..."
cargo run

# Run Python program to encrypt the data
echo -e "\nEncrypting data with Python..."
poetry run python encrypt.py

# Run Rust program again to decrypt the data
echo -e "\nDecrypting data with Rust..."
cargo run

# Final cleanup
cleanup

echo -e "\nDone! All temporary files have been cleaned up." 