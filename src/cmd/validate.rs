use clap::{arg, command, ArgMatches, Command};

use super::CommandType;
use crate::account::{AccountStore, OtpType};
use crate::hotp::validate_hotp;
use crate::totp::validate_totp;

pub fn subcommand() -> Command<'static> {
    command!(CommandType::Validate.as_str())
        .about("Validate a one-time password")
        .args(&[
            arg!(-a --account <NAME> "Account name to validate one-time password for")
                .required(true),
            arg!(-t --token <TOKEN> "One-time password to validate").required(true),
        ])
}

pub fn run_validate(validate_args: &ArgMatches, account_store: AccountStore) {
    let (account_name, token) = match (
        validate_args.value_of("account"),
        validate_args.value_of("token"),
    ) {
        (Some(account_name), Some(token)) => (account_name, token),
        _ => {
            eprintln!("Account name and token are required");
            return;
        }
    };

    let account = account_store.get(account_name);

    match account {
        None => println!("Account not found: {}", account_name),
        Some(account) => {
            let parsed_token = match token.parse::<u32>() {
                Ok(parsed_token) => parsed_token,
                Err(err) => {
                    eprintln!("Unable to parse token: {}", err);
                    return;
                }
            };

            let is_totp = match account.otp_type {
                OtpType::TOTP => true,
                _ => false,
            };

            if is_totp {
                let result = validate_totp(&account, parsed_token);
                match result {
                    Ok(valid_code) => println!("{} valid", valid_code),
                    Err(err) => eprintln!("{}", err),
                }
            } else {
                let result = validate_hotp(&account, parsed_token);
                match result {
                    Ok((_new_counter, valid_code)) => {
                        println!("{} valid", valid_code);

                        // The server implementing this check should update its counter to prevent replay attacks
                        /*
                        account_store.set_counter(account_name, new_counter);

                        match account_store.save() {
                            Ok(_) => println!("Success!"),
                            Err(err) => eprintln!("Unable to save account: {}", err),
                        }
                        */
                    }
                    Err(err) => eprintln!("{}", err),
                }
            }
        }
    }
}
