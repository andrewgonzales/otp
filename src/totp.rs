use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::{Error, ErrorKind};
use std::time::{Duration, SystemTime};

use crate::account::{Account, OtpType};

type HmacSha256 = Hmac<Sha256>;

// Similar to get_hotp, but using SHA-256 digest and u64/32-byte strings
pub fn get_totp(secret: &str, moving_factor: u64) -> u32 {
    let hmac = make_hmac(secret.as_bytes(), moving_factor);
    truncate(hmac) as u32
}

// HMAC_SHA-256 -> 32 byte string
fn make_hmac(secret: &[u8], counter: u64) -> Vec<u8> {
    let mut mac =
        HmacSha256::new_from_slice(secret).expect("Problem with secret, failed to initialize HMAC");
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize();

    result.into_bytes().to_vec()
}

// reduce to 4 byte string
// then s to num mod 10^Digit
fn truncate(hmac: Vec<u8>) -> u64 {
    let base_code = dynamic_truncation(hmac);

    base_code % u64::pow(10, 6)
}

// DT(String) // String = String[0]...String[19]
// Let OffsetBits be the low-order 4 bits of String[19]
// Offset = StToNum(OffsetBits) // 0 <= OffSet <= 15
// Let P = String[OffSet]...String[OffSet+3]
// Return the Last 31 bits of P

// int offset   =  hmac_result[19] & 0xf ;
// int bin_code = (hmac_result[offset]  & 0x7f) << 24
//    | (hmac_result[offset+1] & 0xff) << 16
//    | (hmac_result[offset+2] & 0xff) <<  8
//    | (hmac_result[offset+3] & 0xff) ;
fn dynamic_truncation(hmac: Vec<u8>) -> u64 {
    let offset = (hmac[19] & 0xf) as usize;
    let code = (hmac[offset] as u64 & 0x7f) << 24
        | (hmac[offset + 1] as u64 & 0xff) << 16
        | (hmac[offset + 2] as u64 & 0xff) << 8
        | (hmac[offset + 3] as u64 & 0xff);
    code
}

const TIME_STEP: u64 = 30;
pub struct Clock {}

impl Clock {
    pub fn new() -> Self {
        Clock {}
    }
}
pub trait GetTime {
    fn get_now(&self) -> SystemTime;
}

impl GetTime for Clock {
    fn get_now(&self) -> SystemTime {
        SystemTime::now()
    }
}

pub fn get_totp_moving_factor(clock: &impl GetTime) -> u64 {
    let now = clock.get_now();
    let time = now.duration_since(SystemTime::UNIX_EPOCH);
    let secs = time.unwrap_or(Duration::new(0, 0)).as_secs();
    let periods = secs / TIME_STEP;
    periods
}

pub fn validate_totp(account: &Account, code: u32) -> Result<u32, Error> {
    let window_size = 3;
    if account.otp_type != OtpType::TOTP {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Account is not a TOTP account",
        ));
    };

    println!("entered: {}", code);

    let moving_factor = get_totp_moving_factor(&Clock::new());
    for mf in (moving_factor - window_size)..(moving_factor + window_size) {
        let test_code = get_totp(&account.key, mf);
        println!("Trying {}", test_code);
        if test_code == code {
            return Ok(test_code);
        }
    }

    Err(Error::new(ErrorKind::Other, "Invalid code"))
}

#[cfg(test)]
mod tests {
    use std::ops::Add;

    use super::*;

    const SECRET: &str = "BS5LINH6DJQY2Z4KEXCSUUBA5DXMVMXCXIDBSB2VSR42VJZBUMLQ";

    fn get_test_account() -> Account {
        Account::new(SECRET.to_string(), OtpType::TOTP)
    }

    struct MockClock {}

    impl MockClock {
        pub fn new() -> Self {
            MockClock {}
        }
    }

    impl GetTime for MockClock {
        fn get_now(&self) -> SystemTime {
            SystemTime::UNIX_EPOCH.add(Duration::new(60, 0))
        }
    }

    #[test]
    fn gets_a_totp_value() {
        let moving_factor = 55077978;
        let totp = get_totp(SECRET, moving_factor);

        assert_eq!(totp, 335913);
    }

    #[test]
    fn validates_a_totp_value() {
        let moving_factor = get_totp_moving_factor(&Clock::new());
        let totp = get_totp(SECRET, moving_factor);
        let account = get_test_account();

        assert!(validate_totp(&account, totp).is_ok());
    }

    #[test]
    fn validate_totp_looks_ahead_and_behind() {
        let moving_factor = get_totp_moving_factor(&Clock::new());
        let totp_a = get_totp(SECRET, moving_factor - 2);
        let totp_b = get_totp(SECRET, moving_factor + 2);
        let account = get_test_account();

        assert!(validate_totp(&account, totp_a).is_ok());
        assert!(validate_totp(&account, totp_b).is_ok());
    }

    #[test]
    fn validate_totp_fails_when_wrong() {
        let moving_factor = 55077978; // "distant" past
        let totp = get_totp(SECRET, moving_factor);
        let account = get_test_account();

        assert!(validate_totp(&account, totp).is_err());
    }

    #[test]
    fn gets_moving_factor_from_system_time() {
        let moving_factor = get_totp_moving_factor(&MockClock::new());
        assert_eq!(moving_factor, 2);
    }
}
