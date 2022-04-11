use clap::{arg, command};

use crate::account::AccountStore;

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
        .subcommand(cmd::validate::subcommand())
        .args(&[arg!(-p --pin <PIN> "4-6 character secret pin")
            .required(true)
            .validator(utils::validate_pin)]);

    let matches = cmd.get_matches();
    let pin = matches.value_of("pin").expect("No pin entererd");
    if account_store.is_initialized() && !account_store.validate_pin(pin) {
        return eprintln!("Invalid pin");
    }
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
