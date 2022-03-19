use hmac::{Hmac, Mac};
use sha1::Sha1;

// HOTP https://datatracker.ietf.org/doc/html/rfc4226

// counter-based
// must support tokens without numeric input
// HOTP value > 6 digits value
// re-sync mechanism between client/generator and server/validator
// strong shared secret > 128 bits (160 recommended)

type HmacSha1 = Hmac<Sha1>;

fn main() {
    let secret = "abc";
    let counter = 0;

    let hotp = truncate(make_hmac(secret.as_bytes(), counter));
	println!("hotp: {}", hotp);
}

// HMAC_SHA-1 -> 20 byte string
fn make_hmac(secret: &[u8], counter: i32) -> &str {
	let mut mac = HmacSha1::new_from_slice(secret).expect("Problem with secret, failed to initialize HMAC");
	mac.update(&counter.to_be_bytes());
	let result = mac.finalize();

	println!("result: {:?}", result.into_bytes());
	"12345678"
}

// reduce to 4 byte string
// then s to num mod 10^Digit
fn truncate(hmac: &str) -> &str {
	"123456"
}
