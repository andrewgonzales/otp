use clap::command;
use std::io;

use crate::{account::AccountStore, utils::validate_pin};

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

    loop {
        println!("Enter pin");

        let mut pin = String::new();
        io::stdin()
            .read_line(&mut pin)
            .expect("Failed to read line");

        match pin.trim() {
            code if validate_pin(code).is_ok() => {
                println!("code = {:?}", code);
                if !account_store.is_initialized() {
                    println!("No stored pin found. Run init command.");
                }

                if account_store.validate_pin(code) {
                    break;
                } else {
                    println!("Invalid pin");
                }
            }
            _ => {
                println!("Invalid pin length");
                continue;
            }
        };
    }

    let matches = cmd.get_matches();
    match matches.subcommand() {
        Some(("init", init_args)) => cmd::init::run_init(init_args, account_store),
        Some(("generate", _)) => cmd::generate::run_generate(),
        Some(("add", add_args)) => cmd::add::run_add(add_args, account_store),
        Some(("delete", delete_args)) => cmd::delete::run_delete(delete_args, account_store),
        Some(("list", _)) => cmd::list::run_list(account_store),
        Some(("get", get_args)) => cmd::get::run_get(get_args, account_store),
        Some(("validate", validate_args)) => {
            cmd::validate::run_validate(validate_args, account_store)
        }
        _ => unreachable!("No commands were supplied!"),
    };
}
