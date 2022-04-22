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
