use clap::{arg, command, ArgMatches, Command};

use super::CommandType;
use crate::account::{Account, AccountStore};
use crate::utils::is_base32_key;

pub fn subcommand() -> Command<'static> {
    command!(CommandType::Add.as_str())
        .about("Add an account")
        .args(&[
            arg!(-a --account <NAME> "Account name to create").required(true),
            arg!(-k --key <KEY> "Secret key")
                .required(true)
                .validator(is_base32_key),
        ])
}

pub fn run_add(add_args: &ArgMatches, mut account_store: AccountStore) {
    let account_name = add_args.value_of("account").unwrap();
    let key = add_args.value_of("key").unwrap();

    if account_store.get(account_name).is_some() {
        println!("Account already exists");
    } else {
        let account = Account::new(String::from(key));
        account_store.add(account_name.to_string(), account);
        match account_store.save() {
            Ok(_) => println!("Account \"{}\" successfully created", account_name),
            Err(err) => eprintln!("{}", err),
        }
    }
}
