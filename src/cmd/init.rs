use clap::{arg, command, ArgMatches, Command};

use super::CommandType;
use crate::account::AccountStore;
use crate::utils::encrypt_pw;

pub fn subcommand() -> Command<'static> {
    command!(CommandType::Init.as_str())
        .about("Initialize a new account store")
        .args(&[arg!(-p --pin <PIN> "4-6 character secret pin").required(true)])
}

pub fn run_init(init_args: &ArgMatches, mut account_store: AccountStore) {
    let pin = init_args.value_of("pin").unwrap();

    let encrypted_pin = encrypt_pw(pin);

    match account_store.set_secrets(&encrypted_pin) {
        Ok(_) => println!("Client successfully initialized"),
        Err(err) => eprintln!("{}", err),
    }
}
