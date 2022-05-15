use clap::command;
use std::io::{self, Stdout, Stderr, Write};

use crate::account::{AccountStore, AccountStoreOperations};
use crate::utils::validate_pin;

mod account;
mod cmd;
mod crypto;
mod hotp;
mod totp;
mod utils;

/*
HOTP https://datatracker.ietf.org/doc/html/rfc4226

// counter-based
// must support tokens without numeric input
// HOTP value >= 6 digits value
// re-sync mechanism between client/generator and server/validator
// strong shared secret > 128 bits (160 recommended)

*/

/*
TOTP https://datatracker.ietf.org/doc/html/rfc6238

// uses HOTP with SHA-256 digest
// time-based moving factor based on system time
*/

pub struct OtpWriter {
	pub out: Stdout,
	pub err: Stderr,
}

impl OtpWriter{
	fn new() -> Self {
		OtpWriter { out: io::stdout(), err: io::stderr() }
	}
}

pub trait OutErr {
	fn write_err(&mut self, s: &str);
	fn write(&mut self, s: &str);
}

impl OutErr for OtpWriter {
	fn write_err(&mut self, s: &str) {
		match self.err.write_all(s.as_bytes()) {
			Ok(_) => (),
			Err(e) => eprintln!("{}", e),
		}
	}

	fn write(&mut self, s: &str) {
		match self.out.write_all(s.as_bytes()) {
			Ok(_) => (),
			Err(e) => eprintln!("{}", e),
		}
	}
}

fn main() {
    let account_store = AccountStore::new().expect("Unable to initialize store");
	let mut writer = OtpWriter::new();
    let cmd = command!("otp")
        .about("Time-based and counter-based one-time password generator")
        .version("v0.1.0")
        .subcommand_required(true)
        .subcommand(cmd::init::subcommand())
        .subcommand(cmd::generate::subcommand())
        .subcommand(cmd::add::subcommand())
        .subcommand(cmd::delete::subcommand())
        .subcommand(cmd::list::subcommand())
        .subcommand(cmd::get::subcommand())
        .subcommand(cmd::validate::subcommand());

    let matches = cmd.get_matches();
    match matches.subcommand() {
        Some(("generate", generate_args)) => cmd::generate::run_generate(generate_args),
        Some(("list", _)) => cmd::list::run_list(&account_store),
        Some(("validate", validate_args)) => {
            cmd::validate::run_validate(validate_args, &account_store)
        }
        // These subcommands require a pin
        Some(subcommand) => {
            match check_pin(&account_store) {
                Ok(_) => match subcommand {
                    ("init", init_args) => cmd::init::run_init(init_args, account_store),
                    ("add", add_args) => cmd::add::run_add(add_args, account_store, &mut writer),
					("delete", delete_args) => cmd::delete::run_delete(delete_args, account_store),
					("get", get_args) => cmd::get::run_get(get_args, account_store),
                    _ => println!("Unknown subcommand"),
                },
                Err(err) => println!("{}", err),
            };
        }
        _ => unreachable!("No commands were supplied!"),
    };
}

fn check_pin(account_store: &impl AccountStoreOperations) -> Result<(), String> {
    if !account_store.is_initialized() {
        return Err(String::from(
            "No existing pin found. Run the 'init' command.",
        ));
    } else {
        loop {
            println!("Enter your pin:");

            let mut pin = String::new();
            io::stdin()
                .read_line(&mut pin)
                .expect("Failed to read line");

            match validate_pin(pin.trim(), account_store) {
                Ok(_) => break,
                Err(err) => println!("{}", err),
            }
        }
        Ok(())
    }
}
