use clap::command;
use std::io;

use crate::account::{AccountStore, AccountStoreOperations};
use crate::cmd::CommandType::{Add, Delete, Generate, Get, Init, List, Validate};
use crate::totp::Clock;
use crate::utils::validate_pin;
use crate::writer::OtpWriter;

mod account;
mod cmd;
mod crypto;
mod hotp;
#[cfg(test)]
mod tests;
mod totp;
mod utils;
mod writer;

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

fn main() {
    let mut account_store = AccountStore::new().expect("Unable to initialize store");
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
        Some((gen_cmd, generate_args)) if gen_cmd == Generate.as_str() => {
            cmd::generate::run_generate(generate_args, &mut writer)
        }
        Some((list_cmd, _)) if list_cmd == List.as_str() => cmd::list::run_list(&account_store),
        Some((val_cmd, validate_args)) if val_cmd == Validate.as_str() => {
            cmd::validate::run_validate(validate_args, &account_store)
        }
        // These subcommands require a pin
        Some(subcommand) => {
            match check_pin(&account_store) {
                Ok(_) => match subcommand {
                    (init_cmd, init_args) if init_cmd == Init.as_str() => {
                        cmd::init::run_init(init_args, account_store)
                    }
                    (add_cmd, add_args) if add_cmd == Add.as_str() => {
                        cmd::add::run_add(add_args, &mut account_store, &mut writer)
                    }
                    (delete_cmd, delete_args) if delete_cmd == Delete.as_str() => {
                        cmd::delete::run_delete(delete_args, &mut account_store, &mut writer)
                    }
                    (get_cmd, get_args) if get_cmd == Get.as_str() => {
                        cmd::get::run_get(get_args, &mut account_store, &mut writer, &Clock::new())
                    }
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
