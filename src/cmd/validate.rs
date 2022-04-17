use clap::{arg, command, ArgMatches, Command};

use super::CommandType;
use crate::account::AccountStore;
use crate::hotp::validate_hotp;

pub fn subcommand() -> Command<'static> {
    command!(CommandType::Validate.as_str())
        .about("Validate a one-time password")
        .args(&[
            arg!(-a --account <NAME> "Account name to validate one-time password for")
                .required(true),
            arg!(-t --token <TOKEN> "One-time password to validate").required(true),
        ])
}

pub fn run_validate(validate_args: &ArgMatches, mut account_store: AccountStore) {
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