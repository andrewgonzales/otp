use clap::{arg, command, ArgMatches, Command};

use super::CommandType;
use crate::account::{AccountStoreOperations, OtpType};
use crate::hotp::validate_hotp;
use crate::totp::{validate_totp, GetTime};
use crate::writer::OutErr;

pub fn subcommand() -> Command<'static> {
    command!(CommandType::Validate.as_str())
        .about("Validate a one-time password")
        .args(&[
            arg!(-a --account <NAME> "Account name to validate one-time password for")
                .required(true),
            arg!(-t --token <TOKEN> "One-time password to validate").required(true),
        ])
}

pub fn run_validate<W>(
    validate_args: &ArgMatches,
    account_store: &impl AccountStoreOperations,
    writer: &mut W,
    clock: &impl GetTime,
) where
    W: OutErr,
{
    let (account_name, token) = match (
        validate_args.value_of("account"),
        validate_args.value_of("token"),
    ) {
        (Some(account_name), Some(token)) => (account_name, token),
        _ => {
            writer.write_err("Account name and token are required\n");
            return;
        }
    };

    let account = account_store.get(account_name);

    match account {
        None => writer.write_err(&format!("Account not found: {}\n", account_name)),
        Some(account) => {
            let parsed_token = match token.parse::<u32>() {
                Ok(parsed_token) => parsed_token,
                Err(err) => {
                    writer.write_err(&format!("Unable to parse token: {}\n", err));
                    return;
                }
            };

            let is_totp = match account.otp_type {
                OtpType::TOTP => true,
                _ => false,
            };

            if is_totp {
                let result = validate_totp(&account, parsed_token, clock);
                match result {
                    Ok(valid_code) => writer.write(&format!("{} valid\n", valid_code)),
                    Err(err) => writer.write_err(&format!("{}\n", err)),
                }
            } else {
                let result = validate_hotp(&account, parsed_token);
                match result {
                    Ok((_new_counter, valid_code)) => {
                        writer.write(&format!("{} valid\n", valid_code));

                        // The server implementing this check should update its counter to prevent replay attacks
                        /*
                        account_store.set_counter(account_name, new_counter);

                        match account_store.save() {
                            Ok(_) => println!("Success!"),
                            Err(err) => eprintln!("Unable to save account: {}", err),
                        }
                        */
                    }
                    Err(err) => writer.write_err(&format!("{}\n", err)),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::tests::get_mock_store;
    use crate::cmd::CommandType::Validate;
    use crate::tests::constants::*;
    use crate::tests::mocks::*;
    use crate::tests::utils::get_cmd_args;

    #[test]
    fn validates_totp() {
        let store = get_mock_store();
        let mut writer = MockOtpWriter::new();

        let arg_vec = vec![
            "otp",
            Validate.as_str(),
            "-a",
            ACCOUNT_NAME_2,
            "-t",
            "249961",
        ];
        let validate_args = get_cmd_args(Validate.as_str(), subcommand(), &arg_vec).unwrap();

        run_validate(&validate_args, &store, &mut writer, &MockClock::new());

        let expected_output = format!("249961 valid\n");
        assert_eq!(String::from_utf8(writer.out).unwrap(), expected_output);
        assert_eq!(writer.err, Vec::new());
    }

    #[test]
    fn validates_hotp() {
        let store = get_mock_store();
        let mut writer = MockOtpWriter::new();

        let arg_vec = vec![
            "otp",
            Validate.as_str(),
            "-a",
            ACCOUNT_NAME_1,
            "-t",
            "543440",
        ];
        let validate_args = get_cmd_args(Validate.as_str(), subcommand(), &arg_vec).unwrap();

        run_validate(&validate_args, &store, &mut writer, &MockClock::new());

        let expected_output = format!("543440 valid\n");
        assert_eq!(String::from_utf8(writer.out).unwrap(), expected_output);
        assert_eq!(writer.err, Vec::new());
    }

    #[test]
    fn requires_account_name() {
        let arg_vec = vec!["otp", Validate.as_str(), "-t", "249961"];
        let validate_args = get_cmd_args(Validate.as_str(), subcommand(), &arg_vec);

        assert!(validate_args.is_err());

        let err = validate_args.unwrap_err();
        assert!(err
            .to_string()
            .contains("The following required arguments were not provided:"));

        assert!(err.to_string().contains("--account <NAME>"));
    }

    #[test]
    fn requires_token() {
        let arg_vec = vec!["otp", Validate.as_str(), "-a", ACCOUNT_NAME_2];
        let validate_args = get_cmd_args(Validate.as_str(), subcommand(), &arg_vec);

        assert!(validate_args.is_err());

        let err = validate_args.unwrap_err();
        assert!(err
            .to_string()
            .contains("The following required arguments were not provided:"));

        assert!(err.to_string().contains("--token <TOKEN>"));
    }

    #[test]
    fn errors_when_account_not_found() {
        let store = get_mock_store();
        let mut writer = MockOtpWriter::new();

        let arg_vec = vec![
            "otp",
            Validate.as_str(),
            "-a",
            "not_an_account",
            "-t",
            "249961",
        ];
        let validate_args = get_cmd_args(Validate.as_str(), subcommand(), &arg_vec).unwrap();

        run_validate(&validate_args, &store, &mut writer, &MockClock::new());

        let expected_output = format!("Account not found: {}\n", "not_an_account");
        assert_eq!(String::from_utf8(writer.err).unwrap(), expected_output);
        assert_eq!(writer.out, Vec::new());
    }

    #[test]
    fn errors_when_token_cannot_be_parsed() {
        let store = get_mock_store();
        let mut writer = MockOtpWriter::new();

        let arg_vec = vec![
            "otp",
            Validate.as_str(),
            "-a",
            ACCOUNT_NAME_1,
            "-t",
            "not_a_number",
        ];
        let validate_args = get_cmd_args(Validate.as_str(), subcommand(), &arg_vec).unwrap();

        run_validate(&validate_args, &store, &mut writer, &MockClock::new());

        let expected_output = format!(
            "Unable to parse token: {}\n",
            "invalid digit found in string"
        );
        assert_eq!(String::from_utf8(writer.err).unwrap(), expected_output);
        assert_eq!(writer.out, Vec::new());
    }

    #[test]
    fn does_not_accept_invalid_totp() {
        let store = get_mock_store();
        let mut writer = MockOtpWriter::new();

        let arg_vec = vec![
            "otp",
            Validate.as_str(),
            "-a",
            ACCOUNT_NAME_2,
            "-t",
            "000000",
        ];
        let validate_args = get_cmd_args(Validate.as_str(), subcommand(), &arg_vec).unwrap();

        run_validate(&validate_args, &store, &mut writer, &MockClock::new());

        let expected_output = format!("Invalid code\n");
        assert_eq!(String::from_utf8(writer.err).unwrap(), expected_output);
        assert_eq!(writer.out, Vec::new());
    }

    #[test]
    fn does_not_accept_invalid_hotp() {
        let store = get_mock_store();
        let mut writer = MockOtpWriter::new();

        let arg_vec = vec![
            "otp",
            Validate.as_str(),
            "-a",
            ACCOUNT_NAME_1,
            "-t",
            "000000",
        ];
        let validate_args = get_cmd_args(Validate.as_str(), subcommand(), &arg_vec).unwrap();

        run_validate(&validate_args, &store, &mut writer, &MockClock::new());

        let expected_output = format!("Invalid code\n");
        assert_eq!(String::from_utf8(writer.err).unwrap(), expected_output);
        assert_eq!(writer.out, Vec::new());
    }
}
