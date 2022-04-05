extern crate clap;
extern crate data_encoding;
extern crate rand;

use clap::{arg, command, ArgMatches};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha1::Sha1;
use std::io::{Error, ErrorKind};

use crate::account::{Account, AccountStore};

mod account;

// HOTP https://datatracker.ietf.org/doc/html/rfc4226

// counter-based
// must support tokens without numeric input
// HOTP value >= 6 digits value
// re-sync mechanism between client/generator and server/validator
// strong shared secret > 128 bits (160 recommended)

type HmacSha1 = Hmac<Sha1>;

fn main() {
    let account_store = AccountStore::new().expect("Unable to initialize store");
    let cmd = command!("otp")
        .about("HOTP client and server methods")
        .version("v0.1.0")
        .bin_name("otp")
        .subcommand_required(true)
        .subcommand(command!("generate"))
        .subcommand(
            command!("add").args(&[
                arg!(-a --account <NAME> "Account name to create").required(true),
                arg!(-k --key <KEY> "Secret key")
                    .required(true)
                    .validator(is_base32_key),
            ]),
        )
        .subcommand(command!("get").args(&[
            arg!(-a --account <NAME> "Account name to get one-time password for").required(true),
        ]))
        .subcommand(
            command!("validate").args(&[
                arg!(-a --account <NAME> "Account name to validate one-time password for")
                    .required(true),
                arg!(-t --token <TOKEN> "One-time password to validate").required(true),
            ]),
        );

    let matches = cmd.get_matches();
    match matches.subcommand() {
        Some(("generate", _)) => run_generate(),
        Some(("add", add_args)) => run_add(add_args, account_store),
        Some(("get", get_args)) => run_get(get_args, account_store),
        Some(("validate", validate_args)) => run_validate(validate_args, account_store),
        _ => unreachable!("No commands were supplied!"),
    };

    // let secret = "abc";
    // let counter = 0;

    // let mut hotp = Account::new(String::from(secret));
    // println!("hotp: {:?}", hotp);
    // let otp = get_hotp(secret, counter);
    // println!("otp: {}", otp);
    // let is_valid = validate_hotp(&mut hotp, 974315);
    // println!("is valid: {:?}", is_valid);
    // let is_valid2 = validate_hotp(&mut hotp, 974315);
    // println!("is valid 2: {:?}", is_valid2);
    // let new_secret = generate_secret();
    // println!("new_secret = {:?}", new_secret);
}

fn run_generate() {
    let new_secret_key = generate_secret();
    println!("{}", new_secret_key);
}

fn run_add(add_args: &ArgMatches, mut account_store: AccountStore) {
    println!("account_store = {:?}", account_store.list());

    let account_name = add_args.value_of("account").unwrap();
    let key = add_args.value_of("key").unwrap();

    println!("account = {:?}", account_name);
    println!("key = {:?}", key);

    if account_store.get(account_name).is_some() {
        println!("Account already exists");
    } else {
        let account = Account::new(String::from(key));
        println!("account = {:?}", account);
        account_store.add(account_name.to_string(), account);
        match account_store.save() {
            Ok(_) => println!("Account successfully created"),
            Err(err) => eprintln!("{}", err),
        }
    }
}

fn run_get(get_args: &ArgMatches, mut account_store: AccountStore) {
    let account_name = get_args.value_of("account").unwrap();

    let account = account_store.get(account_name);

    match account {
        None => println!("Account not found: {}", account_name),
        Some(account) => {
            let counter = account.counter.unwrap_or_else(|| 0);
            let otp = get_hotp(&account.key, counter);

            account_store.set_counter(account_name, counter + 1);
            match account_store.save() {
                Ok(_) => println!("{}", otp),
                Err(err) => eprintln!("Unable to save account: {}", err),
            }
        }
    }
}

fn run_validate(validate_args: &ArgMatches, mut account_store: AccountStore) {
    let account_name = validate_args.value_of("account").unwrap();
    let token = validate_args.value_of("token").unwrap();

    let account = account_store.get(account_name);

    match account {
        None => println!("Account not found: {}", account_name),
        Some(account) => {
            let parsed_token = token.parse::<u32>().unwrap();
            let result = validate_hotp(&account, parsed_token);
            match result {
                Ok((new_counter, valid_code)) => {
                    println!("{} valid", valid_code);
                    account_store.set_counter(account_name, new_counter);

                    match account_store.save() {
                        Ok(_) => println!("Success!"),
                        Err(err) => eprintln!("Unable to save account: {}", err),
                    }
                }
                Err(err) => eprintln!("{}", err),
            }
        }
    }
}

// Validate key provided in arguments is a valid base32 encoding
fn is_base32_key(value: &str) -> Result<(), String> {
    let value = value.to_uppercase();
    match BASE32_NOPAD.decode(value.as_bytes()) {
        Ok(_) => Ok(()),
        Err(_) => Err(String::from("the key is not a valid base32 encoding")),
    }
}

fn get_hotp(secret: &str, counter: i32) -> u32 {
    let hmac = make_hmac(secret.as_bytes(), counter);
    truncate(hmac)
}

fn validate_hotp(account: &Account, code: u32) -> Result<(i32, u32), Error> {
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

// Generate a 20 byte random base32 string
fn generate_secret() -> String {
    let mut dest = [0u8; 20];
    OsRng.fill_bytes(&mut dest);
    BASE32_NOPAD.encode(&dest)
}
