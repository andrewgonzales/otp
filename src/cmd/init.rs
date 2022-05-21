use clap::{arg, command, ArgMatches, Command};

use super::CommandType;
use crate::account::AccountStoreOperations;
use crate::crypto::encrypt_pw;
use crate::writer::OutErr;

pub fn subcommand() -> Command<'static> {
    command!(CommandType::Init.as_str())
        .about("Initialize a new account store")
        .args(&[arg!(-p --pin <PIN> "4-6 character secret pin").required(true)])
}

pub fn run_init<W>(
    init_args: &ArgMatches,
    account_store: &mut impl AccountStoreOperations,
    writer: &mut W,
) where
    W: OutErr,
{
    let pin = match init_args.value_of("pin") {
        Some(pin) => pin,
        _ => {
            writer.write_err("Pin is required\n");
            return;
        }
    };

    let encrypted_pin = match encrypt_pw(pin) {
        Ok(encrypted_pin) => encrypted_pin,
        Err(e) => {
            writer.write_err(&format!("Error encrypting password {}\n", e));
            return;
        }
    };

    account_store.set_secrets(&encrypted_pin);

    match account_store.save() {
        Ok(_) => writer.write("Client successfully initialized\n"),
        Err(err) => writer.write_err(&format!("{}\n", err)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::tests::{create_empty_store, get_mock_store};
    use crate::cmd::CommandType::Init;
    use crate::tests::constants::*;
    use crate::tests::mocks::*;
    use crate::tests::utils::get_cmd_args;

    #[test]
    fn initializes_a_new_account_store() {
        let mut store = create_empty_store();
        let mut writer = MockOtpWriter::new();

        let arg_vec = vec!["otp", Init.as_str(), "-p", PIN];
        let init_args = get_cmd_args(CommandType::Init.as_str(), subcommand(), &arg_vec).unwrap();

        assert!(!store.is_initialized());

        run_init(&init_args, &mut store, &mut writer);

        let expected_output = format!("Client successfully initialized\n");
        assert!(store.is_initialized());
        assert_eq!(String::from_utf8(writer.out).unwrap(), expected_output);
        assert_eq!(writer.err, Vec::new());
    }

    #[test]
    #[should_panic]
    fn requires_pin() {
        let mut store = get_mock_store();
        let mut writer = MockOtpWriter::new();

        let arg_vec = vec!["otp", Init.as_str(), "-p", PIN];
        let init_args = get_cmd_args(CommandType::Init.as_str(), subcommand(), &arg_vec).unwrap();

        run_init(&init_args, &mut store, &mut writer);

        let expected_output = format!("Pin is required\n");
        assert_eq!(writer.out, Vec::new());
        assert_eq!(String::from_utf8(writer.err).unwrap(), expected_output);
    }

    #[test]
    fn returns_error_on_save_failure() {
        let mut store = get_mock_store();
        let mut writer = MockOtpWriter::new();

        store.set_should_save_error(true);

        let arg_vec = vec!["otp", Init.as_str(), "-p", PIN];
        let init_args = get_cmd_args(CommandType::Init.as_str(), subcommand(), &arg_vec).unwrap();

        run_init(&init_args, &mut store, &mut writer);

        let expected_output = format!("MockAccountStore failed to save\n");
        assert_eq!(writer.out, Vec::new());
        assert_eq!(String::from_utf8(writer.err).unwrap(), expected_output);
    }
}
