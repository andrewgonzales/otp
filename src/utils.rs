use data_encoding::BASE32_NOPAD;
use rand::rngs::OsRng;
use rand::RngCore;

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
