use argon2::{self, Config, Error};
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;

pub fn encrypt_pw(pw: &str) -> Result<String, Error> {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    let config = Config::default();
    let hash = argon2::hash_encoded(pw.as_bytes(), &salt, &config);
    hash
}

pub fn decrypt_pw(hash: &str, pw: &str) -> bool {
    let verification = argon2::verify_encoded(&hash, &pw.as_bytes());
    match verification {
        Ok(result) => result,
        _ => false,
    }
}


fn generate_nonce() -> [u8; 24] {
    let mut dest = [0u8; 24];
    OsRng.fill_bytes(&mut dest);
    dest
}

pub fn encrypt_string(text: &str, salt: &Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), String> {
    let key = Key::from_slice(&salt); // 32-bytes
    let aead = XChaCha20Poly1305::new(key);

    let nonce_seed = generate_nonce();
    let nonce = XNonce::from_slice(&nonce_seed); // 24-bytes
    let ciphertext = aead
        .encrypt(nonce, text.as_bytes().as_ref())
        .map_err(|e| format!("Encryption failure: {}", e))?;

    Ok((ciphertext, nonce.to_vec()))
}

pub fn decrypt_string(
    ciphertext: &Vec<u8>,
    salt: &Vec<u8>,
    nonce_seed: &Vec<u8>,
) -> Result<String, String> {
    let nonce = XNonce::from_slice(&nonce_seed);
    let key = Key::from_slice(&salt); // 32-bytes
    let aead = XChaCha20Poly1305::new(key);

    let plaintext_bytes = aead
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| format!("Decryption failure: {}", e))?;

    let plaintext = String::from_utf8(plaintext_bytes);
    match plaintext {
        Ok(text) => Ok(text),
        Err(e) => Err(format!("Decryption failure: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_and_verifies_a_password() {
        let password = "some_good_password!@#";
        let hash = encrypt_pw(password).unwrap();
        assert!(password != &hash);
        assert!(decrypt_pw(&hash, password));
    }

    #[test]
    fn fails_to_verify_a_password_with_wrong_hash() {
        let password = "some_good_password!@#";
        let hash = encrypt_pw(password).unwrap();
        assert!(!decrypt_pw(&hash, "wrong_password"));
    }

    #[test]
    fn generates_a_24_byte_nonce() {
        let nonce = generate_nonce();
        assert_eq!(nonce.len(), 24);
    }

    #[test]
    fn encrypts_and_decrypts_a_string() {
        let hash = encrypt_pw("123456").unwrap();
        let salt = hash.into_bytes()[..32].to_vec();

        let text = "some_text";
        let (ciphertext, nonce) = encrypt_string(text, &salt).unwrap();
        assert!(ciphertext.len() > 0);
        assert!(ciphertext != text.as_bytes());

        let decrypted_text = decrypt_string(&ciphertext, &salt, &nonce).unwrap();
        assert_eq!(text, decrypted_text);
    }
}
