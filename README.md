# Python-Rust Encryption Demo

This project demonstrates secure communication between Python and Rust using X25519 key exchange and AES-GCM encryption.

## Prerequisites

- Rust and Cargo
- Python 3.7+
- Poetry (Python package manager)

## Quick Start

1. Clone the repository:

```bash
git clone <repository-url>
cd crypto-test
```

2. Install Python dependencies:

```bash
poetry install
```

3. Build the Rust project:

```bash
cargo build
```

4. Run the demo:

```bash
./run.sh
```

## How it Works

1. The Rust program generates an X25519 keypair and saves its public key
2. Python reads Rust's public key, generates its own keypair, and saves its public key
3. Both programs compute the same shared secret using X25519 Diffie-Hellman
4. Python encrypts JSON data using AES-GCM with the shared secret
5. Rust decrypts the data using the same shared secret

## Sample Output

```
Generating Rust public key...
Rust public key (Base64): <base64-encoded-key>

Encrypting data with Python...
Python public key (Base64): <base64-encoded-key>
Data encrypted and saved to 'encrypted.bin'

Decrypting data with Rust...
Decrypted JSON data:
{
    "message": "Hello from Python!",
    "number": 42,
    "list": [1, 2, 3]
}
```

## File Structure

- `src/main.rs` - Rust program for key generation and decryption
- `encrypt.py` - Python program for key generation and encryption
- `run.sh` - Shell script to demonstrate the full workflow
- `pyproject.toml` - Python project dependencies
- `Cargo.toml` - Rust project dependencies

## Dependencies

### Rust

- x25519-dalek - For X25519 key exchange
- aes-gcm - For AES-GCM encryption
- serde_json - For JSON handling
- base64 - For key encoding

### Python

- cryptography - For X25519 and AES-GCM operations

## Security Notes

- This is a demonstration project and may need additional security measures for production use
- The shared secret is derived using X25519 Diffie-Hellman key exchange
- AES-GCM provides both confidentiality and authenticity
- Temporary keys and encrypted data are automatically cleaned up after demonstration

```

```
