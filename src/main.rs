use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use serde_json::Value;
use std::fs;
use std::path::Path;
use x25519_dalek::{PublicKey, StaticSecret};

fn main() {
    // Generate our keypair
    let private_key = StaticSecret::random_from_rng(rand::thread_rng());
    let public_key = PublicKey::from(&private_key);

    // Save our public key for Python to use
    fs::write("rust_key.pub", public_key.as_bytes()).expect("Failed to write public key");

    println!(
        "Rust public key (Base64): {}",
        BASE64.encode(public_key.as_bytes())
    );

    if !Path::new("encrypted.bin").exists() {
        println!("\nWaiting for encrypted data...");
        println!("Please run: poetry run python encrypt.py");
        println!("Then run this program again to decrypt the data.");
        return;
    }

    // Read Python's public key
    let python_public_bytes =
        fs::read("python_key.pub").expect("Failed to read Python's public key");
    let python_public =
        PublicKey::from(<[u8; 32]>::try_from(python_public_bytes.as_slice()).unwrap());

    // Compute shared secret
    let shared_secret = private_key.diffie_hellman(&python_public);

    // Read the encrypted data
    let encrypted_data = fs::read("encrypted.bin").expect("Failed to read encrypted data");

    // In NaCl's Box, the structure is: nonce (24 bytes) || encrypted_data
    let nonce = &encrypted_data[..24];
    let ciphertext = &encrypted_data[24..];

    // Create cipher instance with the first 32 bytes of the shared secret
    let cipher = ChaCha20Poly1305::new_from_slice(&shared_secret.as_bytes()[..32])
        .expect("Failed to create cipher");

    // Decrypt the message
    let decrypted = cipher
        .decrypt(nonce.into(), ciphertext)
        .expect("Failed to decrypt");

    // Parse JSON
    let json_str = String::from_utf8(decrypted).expect("Failed to decode UTF-8");
    let json: Value = serde_json::from_str(&json_str).expect("Failed to parse JSON");

    println!("\nDecrypted JSON data:");
    println!("{}", serde_json::to_string_pretty(&json).unwrap());
}
