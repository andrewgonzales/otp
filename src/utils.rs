use argon2::{self, Config};
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use data_encoding::BASE32_NOPAD;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::account::AccountStore;

// Generate a 20 byte random base32 string
pub fn generate_secret() -> String {
    let mut dest = [0u8; 20];
    OsRng.fill_bytes(&mut dest);
    BASE32_NOPAD.encode(&dest)
}

// Validate key provided in arguments is a valid base32 encoding
pub fn is_base32_key(value: &str) -> Result<(), String> {
    let value = value.to_uppercase();
    match BASE32_NOPAD.decode(value.as_bytes()) {
        Ok(_) => Ok(()),
        Err(_) => Err(String::from("the key is not a valid base32 encoding")),
    }
}

pub fn encrypt_pw(pw: &str) -> String {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    let config = Config::default();
    let hash = argon2::hash_encoded(pw.as_bytes(), &salt, &config).unwrap();
    hash
}

pub fn decrypt_pw(hash: &str, pw: &str) -> bool {
    argon2::verify_encoded(&hash, &pw.as_bytes()).unwrap()
}

pub fn validate_pin(pin: &str, account_store: &AccountStore) -> Result<(), String> {
    if pin.len() < 4 || pin.len() > 6 {
        return Err(String::from("PIN must be between 4 and 6 characters"));
    }

    if !account_store.is_initialized() {
        return Err(String::from(
            "No existing pin found. Run the 'init' command.",
        ));
    }

    if !account_store.validate_pin(pin) {
        return Err(String::from("Invalid pin"));
    }

    Ok(())
}

fn generate_encryption_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

fn generate_nonce() -> [u8; 24] {
    let mut dest = [0u8; 24];
    OsRng.fill_bytes(&mut dest);
    dest
}

pub fn encrypt_string(text: &str) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
	let some_salt = generate_encryption_key();
    let key = Key::from_slice(&some_salt); // 32-bytes
    let aead = XChaCha20Poly1305::new(key);

    let nonce_seed = generate_nonce();
    let nonce = XNonce::from_slice(&nonce_seed); // 24-bytes
    let ciphertext = aead
        .encrypt(nonce, text.as_bytes().as_ref())
        .expect("encryption failure!");

    Ok((ciphertext, some_salt.to_vec(), nonce.to_vec()))
}

pub fn decrypt_string(ciphertext: &Vec<u8>, salt: &Vec<u8>, nonce_seed: &Vec<u8>) -> Result<String, String> {
    let nonce = XNonce::from_slice(nonce_seed);
    let key = Key::from_slice(salt); // 32-bytes
    let aead = XChaCha20Poly1305::new(key);

    let plaintext = aead
        .decrypt(nonce, ciphertext.as_ref())
        .expect("decryption failure!");

    Ok(String::from_utf8(plaintext).unwrap())
}
