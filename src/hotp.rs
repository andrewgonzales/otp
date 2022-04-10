use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::io::{Error, ErrorKind};

use crate::account::Account;

type HmacSha1 = Hmac<Sha1>;

pub fn get_hotp(secret: &str, counter: i32) -> u32 {
    let hmac = make_hmac(secret.as_bytes(), counter);
    truncate(hmac)
}

pub fn validate_hotp(account: &Account, code: u32) -> Result<(i32, u32), Error> {
    let window_size = 10;
    let counter = match account.counter {
        Some(value) => value,
        None => 0,
    };

    println!("entered: {}", code);

    for i in counter..counter + window_size {
        let test_code = get_hotp(&account.key, i);
        println!("Trying {}", test_code);
        if test_code == code {
            return Ok((i, test_code));
        }
    }

    Err(Error::new(ErrorKind::Other, "Invalid code"))
}

// HMAC_SHA-1 -> 20 byte string
fn make_hmac(secret: &[u8], counter: i32) -> Vec<u8> {
    let mut mac =
        HmacSha1::new_from_slice(secret).expect("Problem with secret, failed to initialize HMAC");
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize();

    result.into_bytes().to_vec()
}

// reduce to 4 byte string
// then s to num mod 10^Digit
fn truncate(hmac: Vec<u8>) -> u32 {
    let base_code = dynamic_truncation(hmac);

    base_code % u32::pow(10, 6)
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
fn dynamic_truncation(hmac: Vec<u8>) -> u32 {
    let offset = (hmac[19] & 0xf) as usize;
    let code = (hmac[offset] as u32 & 0x7f) << 24
        | (hmac[offset + 1] as u32 & 0xff) << 16
        | (hmac[offset + 2] as u32 & 0xff) << 8
        | (hmac[offset + 3] as u32 & 0xff);
    code
}
