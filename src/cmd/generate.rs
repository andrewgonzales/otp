use clap::{command, Command};

use crate::utils::generate_secret;

use super::CommandType;

pub fn subcommand() -> Command<'static> {
    command!(CommandType::Generate.as_str()).about("Generate a Base32 secret key")
}

pub fn run_generate() {
    let new_secret_key = generate_secret();
    println!("{}", new_secret_key);
}
