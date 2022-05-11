use clap::{arg, command, ArgMatches, Command};

use super::CommandType;
use crate::account::{Account, AccountStore, OtpType};
use crate::utils::is_base32_key;

pub fn subcommand() -> Command<'static> {
    command!(CommandType::Add.as_str())
        .about("Add an account")
        .args(&[
            arg!(-a --account <NAME> "Account name to create").required(true),
            arg!(-k --key <KEY> "Secret key")
                .required(true)
                .validator(is_base32_key),
			arg!(-c --hotp "Counter-based HOTP (Time-based TOTP is default)").required(false),
        ])
}

pub fn run_add(add_args: &ArgMatches, mut account_store: AccountStore) {
    let (account_name, key) = match (add_args.value_of("account"), add_args.value_of("key")) {
        (Some(account_name), Some(key)) => (account_name, key),
        _ => {
            eprintln!("Account name and key are required");
            return;
        }
    };

    if account_store.get(account_name).is_some() {
        eprintln!("Account already exists");
    } else {
		let is_hotp = add_args.is_present("hotp");
		let otp_type = if is_hotp {
			OtpType::HOTP(Some(0))
		} else {
			OtpType::TOTP
		};
        let account = Account::new(String::from(key), otp_type);
        account_store.add(account_name.to_string(), account);
        match account_store.save() {
            Ok(_) => println!("Account \"{}\" successfully created", account_name),
            Err(err) => eprintln!("{}", err),
        }
    }
}
