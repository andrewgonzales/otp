use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::fmt::Debug;
use std::io::{Error, ErrorKind};

// HOTP https://datatracker.ietf.org/doc/html/rfc4226

// counter-based
// must support tokens without numeric input
// HOTP value >= 6 digits value
// re-sync mechanism between client/generator and server/validator
// strong shared secret > 128 bits (160 recommended)

type HmacSha1 = Hmac<Sha1>;

#[derive(Debug)]
struct HOTP<'a> {
    secret: &'a str,
    counter: i32,
}

impl HOTP<'_> {
    fn new(secret: &'static str) -> Self {
        HOTP { secret, counter: 0 }
    }
}

fn main() {
    let secret = "abc";
    let counter = 0;

    let mut hotp = HOTP::new(secret);
    println!("hotp: {:?}", hotp);
    let otp = get_hotp(secret, counter);
    println!("otp: {}", otp);
	let is_valid = validate_hotp(&mut hotp, 974315);
	println!("is valid: {:?}", is_valid);
	let is_valid2 = validate_hotp(&mut hotp, 974315);
	println!("is valid 2: {:?}", is_valid2);
}

fn get_hotp(secret: &str, counter: i32) -> u32 {
    let hmac = make_hmac(secret.as_bytes(), counter);
    truncate(hmac)
}

fn validate_hotp(hotp: &mut HOTP, code: u32) -> Result<u32, Error> {
    let expected_code = get_hotp(hotp.secret, hotp.counter);
	println!("expected: {}", expected_code);
	println!("entered: {}, {}", code, code == expected_code);
    let result = match code {
        n if n == expected_code => {
			hotp.counter += 1;
			Ok(code)
		},
        _ => Err(Error::new(ErrorKind::PermissionDenied, "Code didn't match")),
    };

    result
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
    println!("hmac: {:?}", hmac);
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
