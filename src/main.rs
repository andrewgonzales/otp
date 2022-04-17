use clap::command;
use std::io;

use crate::account::AccountStore;
use crate::utils::validate_pin;

mod account;
mod cmd;
mod hotp;
mod utils;

// HOTP https://datatracker.ietf.org/doc/html/rfc4226

// counter-based
// must support tokens without numeric input
// HOTP value >= 6 digits value
// re-sync mechanism between client/generator and server/validator
// strong shared secret > 128 bits (160 recommended)

fn main() {
	let account_store = AccountStore::new().expect("Unable to initialize store");
    let cmd = command!("hotp")
        .about("HOTP client and server methods")
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
        Some(("init", init_args)) => cmd::init::run_init(init_args, account_store),
        Some(("generate", _)) => cmd::generate::run_generate(),
        Some(("list", _)) => cmd::list::run_list(account_store),
        Some(("validate", validate_args)) => {
            cmd::validate::run_validate(validate_args, account_store)
        }
        // These subcommands require a pin
        Some(subcommand) => {
            match check_pin(&account_store) {
                Ok(_) => match subcommand {
                    ("add", add_args) => cmd::add::run_add(add_args, account_store),
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

fn check_pin(account_store: &AccountStore) -> Result<(), String> {
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

            match validate_pin(pin.trim(), &account_store) {
                Ok(_) => break,
                Err(err) => println!("{}", err),
            }
        }
        Ok(())
    }
}
