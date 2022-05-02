use clap::{arg, command, ArgMatches, Command};

use super::CommandType;
use crate::account::AccountStore;
use crate::crypto::encrypt_pw;

pub fn subcommand() -> Command<'static> {
    command!(CommandType::Init.as_str())
        .about("Initialize a new account store")
        .args(&[arg!(-p --pin <PIN> "4-6 character secret pin").required(true)])
}

pub fn run_init(init_args: &ArgMatches, mut account_store: AccountStore) {
    let pin = match init_args.value_of("pin") {
        Some(pin) => pin,
        _ => {
            eprintln!("Pin is required");
            return;
        }
    };

    let encrypted_pin = match encrypt_pw(pin) {
        Ok(encrypted_pin) => encrypted_pin,
        Err(e) => {
            println!("Error encrypting passwordr {}", e);
            return;
        }
    };

    account_store.set_secrets(&encrypted_pin);

	match account_store.save() {
        Ok(_) => println!("Client successfully initialized"),
        Err(err) => eprintln!("{}", err),
    }
}
