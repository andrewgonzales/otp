use clap::{arg, command, ArgMatches, Command};

use super::CommandType;
use crate::account::AccountStore;
use crate::hotp::get_hotp;

pub fn subcommand() -> Command<'static> {
    command!(CommandType::Get.as_str())
        .about("Get a one-time password")
        .args(&[
            arg!(-a --account <NAME> "Account name to get one-time password for").required(true),
        ])
}

pub fn run_get(get_args: &ArgMatches, mut account_store: AccountStore) {
    let account_name = get_args.value_of("account").unwrap();

    let account = account_store.get(account_name);

    match account {
        None => println!("Account not found: {}", account_name),
        Some(account) => {
            let counter = account.counter.unwrap_or_else(|| 0);
            let otp = get_hotp(&account.key, counter);

            account_store.set_counter(account_name, counter + 1);
            match account_store.save() {
                Ok(_) => println!("{}", format!("{:0>6}", otp)),
                Err(err) => eprintln!("Unable to save account: {}", err),
            }
        }
    }
}
