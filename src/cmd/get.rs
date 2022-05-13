use clap::{arg, command, ArgMatches, Command};

use super::CommandType;
use crate::account::{AccountStore, OtpType};
use crate::hotp::get_hotp;
use crate::totp::{get_totp, get_totp_moving_factor, Clock};

pub fn subcommand() -> Command<'static> {
    command!(CommandType::Get.as_str())
        .about("Get a one-time password")
        .args(&[
            arg!(-a --account <NAME> "Account name to get one-time password for").required(true),
        ])
}

pub fn run_get(get_args: &ArgMatches, mut account_store: AccountStore) {
    let account_name = match get_args.value_of("account") {
        Some(account_name) => account_name,
        _ => {
            eprintln!("Account name is required");
            return;
        }
    };

    let account = account_store.get(account_name);

    match account {
        None => println!("Account not found: {}", account_name),
        Some(account) => {
            let (otp, new_counter) = match account.otp_type {
                OtpType::TOTP => (
                    get_totp(&account.key, get_totp_moving_factor(&Clock::new())),
                    None,
                ),
                OtpType::HOTP(maybe_counter) => {
                    let counter = maybe_counter.unwrap_or(0);
                    (get_hotp(&account.key, counter), Some(counter + 1))
                }
            };

            if new_counter.is_some() {
                account_store.set_counter(account_name, new_counter.unwrap_or(1));
            }

            match account_store.save() {
                Ok(_) => println!("{}", format!("{:0>6}", otp)),
                Err(err) => eprintln!("Unable to save account: {}", err),
            }
        }
    }
}
