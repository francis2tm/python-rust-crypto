import json
import base64
import os
from nacl.public import PrivateKey, PublicKey, Box
from nacl.bindings import crypto_scalarmult

# Sample JSON data
data = {
    "message": "Hello from Python!",
    "number": 42,
    "list": [1, 2, 3]
}

def main():
    # Generate our private key
    private_key = PrivateKey.generate()
    
    # Get our public key
    public_key = private_key.public_key
    
    # Save our public key for Rust to use
    with open("python_public.key", "wb") as f:
        f.write(public_key.encode())
    
    print("Python public key (Base64):", base64.b64encode(bytes(public_key)).decode())
    
    # Check if Rust's public key exists
    if not os.path.exists("rust_public.key"):
        print("\nWaiting for Rust's public key...")
        print("Please run: cargo run")
        print("Then press Enter to continue...")
        input()
    
    # Read Rust's public key
    try:
        with open("rust_public.key", "rb") as f:
            rust_public_key = PublicKey(f.read())
    except FileNotFoundError:
        print("Error: rust_public.key not found. Please run the Rust program first.")
        return
    
    # Create a shared secret using Diffie-Hellman
    shared_secret = crypto_scalarmult(private_key.encode(), rust_public_key.encode())
    
    # Create an encryption box
    box = Box(private_key, rust_public_key)
    
    # Convert our data to bytes
    message = json.dumps(data).encode('utf-8')
    
    # Encrypt the message
    encrypted = box.encrypt(message)
    
    # Save the encrypted message
    with open("encrypted.bin", "wb") as f:
        f.write(encrypted)
    
    print("\nData encrypted and saved to 'encrypted.bin'")
    print("Encrypted data (Base64):", base64.b64encode(encrypted).decode())

if __name__ == "__main__":
    main() 