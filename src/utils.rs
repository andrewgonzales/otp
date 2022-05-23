use data_encoding::BASE32_NOPAD;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::account::AccountStoreOperations;

// Generate a 20 byte random base32 string
pub fn generate_secret() -> String {
    let mut dest = [0u8; 20];
    OsRng.fill_bytes(&mut dest);
    BASE32_NOPAD.encode(&dest)
}

// Generate a 32 byte random base32 string
pub fn generate_secret_32() -> String {
    let mut dest = [0u8; 32];
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

pub fn validate_pin(pin: &str, account_store: &impl AccountStoreOperations) -> Result<(), String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::tests::create_empty_store;
    use crate::account::MockAccountStore;
    use crate::crypto::encrypt_pw;
    use crate::tests::constants::PIN;

    fn get_mock_store(include_hash: bool) -> MockAccountStore {
        let mut account_store = create_empty_store();
        match include_hash {
            true => {
                let hash = encrypt_pw(PIN).expect("Failed to encrypt pin");
                account_store.set_secrets(&hash);
                account_store
            }
            false => account_store,
        }
    }

    #[test]
    fn generates_a_20_byte_base32_secret() {
        let secret = generate_secret();
        assert_eq!(secret.len(), 32);
        assert!(BASE32_NOPAD.decode(secret.as_bytes()).is_ok());
    }

    #[test]
    fn is_base32_key_returns_error_if_not_base32() {
        assert_eq!(
            is_base32_key("not_base32"),
            Err(String::from("the key is not a valid base32 encoding"))
        );
    }

    #[test]
    fn is_base32_key_returns_ok_if_base32() {
        assert_eq!(is_base32_key("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"), Ok(()));
    }

    #[test]
    fn validate_pin_checks_pin_length() {
        let account_store = get_mock_store(false);
        assert_eq!(
            validate_pin("123", &account_store),
            Err(String::from("PIN must be between 4 and 6 characters"))
        );

        let account_store_2 = get_mock_store(false);
        assert_eq!(
            validate_pin("1234567", &account_store_2),
            Err(String::from("PIN must be between 4 and 6 characters"))
        );
    }

    #[test]
    fn validate_pin_returns_error_if_pin_is_invalid() {
        let account_store = get_mock_store(true);
        assert_eq!(
            validate_pin("1234", &account_store),
            Err(String::from("Invalid pin"))
        );
    }

    #[test]
    fn validate_pin_returns_error_if_account_store_is_not_initialized() {
        let account_store = get_mock_store(false);
        assert_eq!(
            validate_pin("1234", &account_store),
            Err(String::from(
                "No existing pin found. Run the 'init' command."
            ))
        );
    }

    #[test]
    fn validate_pin_returns_ok_if_pin_is_valid() {
        let account_store = get_mock_store(true);
        assert_eq!(validate_pin("123456", &account_store), Ok(()));
    }
}
