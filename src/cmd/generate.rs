use clap::{arg, command, ArgMatches, Command};

use crate::utils::{generate_secret, generate_secret_32};

use super::CommandType;

pub fn subcommand() -> Command<'static> {
    command!(CommandType::Generate.as_str())
        .about("Generate a Base32 secret key")
        .args(&[arg!(-c --counter "Key for counter-based HOTP (time-based TOTP is default)").required(false)])
}

pub fn run_generate(generate_args: &ArgMatches) {
	let is_hotp = generate_args.is_present("counter");
    let new_secret_key = match is_hotp {
		true => generate_secret_32(),
		false => generate_secret(),
	};
    println!("{}", new_secret_key);
}
