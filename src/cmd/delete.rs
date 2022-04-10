use clap::{arg, command, ArgMatches, Command};

use super::CommandType;
use crate::account::AccountStore;

pub fn subcommand() -> Command<'static> {
    command!(CommandType::Delete.as_str())
        .about("Delete an account")
        .args(&[arg!(-a --account <NAME> "Account name to delete").required(true)])
}

pub fn run_delete(delete_args: &ArgMatches, mut account_store: AccountStore) {
    let account_name = delete_args.value_of("account").unwrap();

    let result = account_store.delete(account_name);

    match result {
        Some(_) => match account_store.save() {
            Ok(_) => println!("Account successfully deleted"),
            Err(err) => eprintln!("{}", err),
        },
        None => eprintln!("Account not found: {}", account_name),
    }
}
