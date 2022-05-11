use std::time::SystemTime;

// mod totp;

// TOTP https://datatracker.ietf.org/doc/html/rfc6238

// uses HOTP with SHA-256 digest
// time-based moving factor based on system time

const TIME_STEP: u64 = 30;
fn main() {
    //    let key = utils::generate_secret_32();
    let key = String::from("MTDXIJSGWCEVRZ7LVUQSQSASEMOLENCFAWIV7PC2NPBWAQTNS7LA");
    println!("{}", key);
    let time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH);
    // println!("time = {:?}", time);
	// let secs = 60;
	let secs = time.unwrap().as_secs();
	// let time_step = 30;
	let periods = secs / TIME_STEP;
	println!("periods = {:?}", periods);
    // let totp = totp::get_totp(&key, periods);
    // println!("totp = {:?}", totp);
}
