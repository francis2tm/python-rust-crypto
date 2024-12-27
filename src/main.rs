use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde_json::Value;
use std::fs;
use std::path::Path;
use x25519_dalek::{PublicKey, StaticSecret};

fn main() {
    // Only generate new keypair if the public key doesn't exist
    let (private_key, public_key) = if !Path::new("rust_key.pub").exists() {
        let private_key = StaticSecret::random_from_rng(rand::thread_rng());
        let public_key = PublicKey::from(&private_key);

        // Save our public key for Python to use
        fs::write("rust_key.pub", public_key.as_bytes()).expect("Failed to write public key");

        // Save our private key
        fs::write("rust_key.private", private_key.to_bytes()).expect("Failed to write private key");

        (private_key, public_key)
    } else {
        // Read existing private key (you'll need to save this)
        let private_key_bytes = fs::read("rust_key.private").expect("Failed to read private key");
        let private_key =
            StaticSecret::from(<[u8; 32]>::try_from(private_key_bytes.as_slice()).unwrap());
        let public_key = PublicKey::from(&private_key);
        (private_key, public_key)
    };

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

    // In AES-GCM, we'll use a 12-byte nonce
    let nonce = &encrypted_data[..12];
    let ciphertext = &encrypted_data[12..];

    // Create cipher instance with the first 32 bytes of the shared secret
    let cipher = Aes256Gcm::new_from_slice(&shared_secret.as_bytes()[..32])
        .expect("Failed to create cipher");

    // Decrypt the message
    let decrypted = match cipher.decrypt(nonce.into(), ciphertext) {
        Ok(data) => data,
        Err(e) => {
            println!("Decryption failed: {}", e);
            return;
        }
    };

    // Parse JSON
    let json_str = String::from_utf8(decrypted).expect("Failed to decode UTF-8");
    let json: Value = serde_json::from_str(&json_str).expect("Failed to parse JSON");

    println!("\nDecrypted JSON data:");
    println!("{}", serde_json::to_string_pretty(&json).unwrap());
}
