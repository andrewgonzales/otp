use clap::{arg, command, ArgMatches, Command};

use super::CommandType;
use crate::account::{Account, AccountStoreOperations, OtpType};
use crate::utils::is_base32_key;
use crate::writer::OutErr;

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

pub fn run_add<W>(
    add_args: &ArgMatches,
    account_store: &mut impl AccountStoreOperations,
    writer: &mut W,
) where
    W: OutErr,
{
    let (account_name, key) = match (add_args.value_of("account"), add_args.value_of("key")) {
        (Some(account_name), Some(key)) => (account_name, key),
        _ => {
            writer.write_err("Account name and key are required\n");
            return;
        }
    };

    if account_store.get(account_name).is_some() {
        writer.write_err("Account already exists\n");
    } else {
        let is_hotp = add_args.is_present("hotp");
        let otp_type = match is_hotp {
            true => OtpType::HOTP(Some(0)),
            false => OtpType::TOTP,
        };
        let account = Account::new(String::from(key), otp_type);
        account_store.add(account_name.to_string(), account);
        match account_store.save() {
            Ok(_) => writer.write(&format!(
                "Account \"{}\" successfully created",
                account_name
            )),
            Err(err) => writer.write_err(&format!("{}", err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::tests::get_mock_store;
    use crate::tests::constants::*;
    use crate::tests::mocks::*;
    use crate::tests::utils::get_cmd_args;

    #[test]
    fn adds_an_account() {
        let mut store = get_mock_store();
        let mut writer = MockOtpWriter::new();

        let arg_vec = vec!["otp", "add", "-a", ACCOUNT_NAME, "-k", TOTP_KEY];
        let add_args = get_cmd_args("add", subcommand(), &arg_vec).unwrap();

        run_add(&add_args, &mut store, &mut writer);

        assert_eq!(store.get(ACCOUNT_NAME).unwrap().key, TOTP_KEY);
        assert_eq!(store.get(ACCOUNT_NAME).unwrap().otp_type, OtpType::TOTP);

        let expected_output = format!("Account \"{}\" successfully created", ACCOUNT_NAME);
        assert_eq!(writer.out, expected_output.as_bytes());
        assert_eq!(writer.err, Vec::new());
    }

    #[test]
    fn adds_an_account_with_hotp() {
        let mut store = get_mock_store();
        let mut writer = MockOtpWriter::new();

        let arg_vec = vec!["otp", "add", "-a", ACCOUNT_NAME, "-k", HOTP_KEY, "-c"];
        let add_args = get_cmd_args("add", subcommand(), &arg_vec).unwrap();

        run_add(&add_args, &mut store, &mut writer);

        assert_eq!(store.get(ACCOUNT_NAME).unwrap().key, HOTP_KEY);
        assert_eq!(
            store.get(ACCOUNT_NAME).unwrap().otp_type,
            OtpType::HOTP(Some(0))
        );

        let expected_output = format!("Account \"{}\" successfully created", ACCOUNT_NAME);
        assert_eq!(writer.out, expected_output.as_bytes());
        assert_eq!(writer.err, Vec::new());
    }

    #[test]
    #[should_panic]
    fn requires_account_name() {
        let arg_vec = vec!["otp", "add", "-k", TOTP_KEY];
        let add_args = get_cmd_args("add", subcommand(), &arg_vec);

        assert!(add_args.is_err());

        let err = add_args.unwrap_err();

        assert!(
            err.to_string()
                .contains("the following required arguments were not provided: account"),
            "{}",
            err
        );
    }

    #[test]
    #[should_panic]
    fn requires_key() {
        let arg_vec = vec!["otp", "add", "-a", ACCOUNT_NAME];
        let add_args = get_cmd_args("add", subcommand(), &arg_vec);

        assert!(add_args.is_err());

        let err = add_args.unwrap_err();

        assert!(
            err.to_string()
                .contains("the following required arguments were not provided: key"),
            "{}",
            err
        );
    }

    #[test]
    fn errors_if_account_exists() {
        let mut store = get_mock_store();
        let mut writer = MockOtpWriter::new();

        let arg_vec = vec!["otp", "add", "-a", "google", "-k", TOTP_KEY];
        let add_args = get_cmd_args("add", subcommand(), &arg_vec).unwrap();

        run_add(&add_args, &mut store, &mut writer);

        assert_eq!(writer.err, "Account already exists\n".as_bytes());
        assert_eq!(writer.out, Vec::new());
    }

    #[test]
    fn validates_key_encoding() {
        let arg_vec = vec!["otp", "add", "-a", "google", "-k", "invalid-key!"];
        let add_args = get_cmd_args("add", subcommand(), &arg_vec);

        assert!(add_args.is_err());

        let err = add_args.unwrap_err();

        assert!(
            err.to_string()
                .contains("the key is not a valid base32 encoding"),
            "{}",
            err
        );
    }

    #[test]
    fn errors_on_save_failure() {
        let mut store = get_mock_store();
        let mut writer = MockOtpWriter::new();

        store.set_should_save_error(true);

        let arg_vec = vec!["otp", "add", "-a", ACCOUNT_NAME, "-k", TOTP_KEY];
        let add_args = get_cmd_args("add", subcommand(), &arg_vec).unwrap();

        run_add(&add_args, &mut store, &mut writer);

        assert_eq!(
            String::from_utf8_lossy(&writer.err.to_vec()),
            "MockAccountStore failed to save"
        );
        assert_eq!(writer.out, Vec::new());
    }
}
