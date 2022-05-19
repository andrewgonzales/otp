use clap::{ArgMatches, Command};

pub fn get_cmd_args(
    command_str: &str,
    subcommand: Command,
    arg_vec: &Vec<&str>,
) -> Result<ArgMatches, clap::Error> {
    let matches = Command::new("otp")
        .subcommand(subcommand)
        .try_get_matches_from(arg_vec)?;

    let arg_matches = matches.subcommand().unwrap();
    let cmd_args = match arg_matches {
        (cmd, cmd_args) if cmd == command_str => cmd_args.clone(),
        _ => panic!("Expected {} subcommand", command_str),
    };
    Ok(cmd_args)
}
