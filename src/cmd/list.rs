use clap::{command, Command};

use super::CommandType;
use crate::account::AccountStore;

pub fn subcommand() -> Command<'static> {
    command!(CommandType::List.as_str()).about("List all accounts")
}

pub fn run_list(account_store: AccountStore) {
    println!("Accounts:");
    for name in account_store.list() {
        println!("{}", name);
    }
}