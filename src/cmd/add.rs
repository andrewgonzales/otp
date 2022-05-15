use clap::{arg, command, ArgMatches, Command};

use super::super::OutErr;
use super::CommandType;
use crate::account::{Account, AccountStoreOperations, OtpType};
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

pub fn run_add<W>(
    add_args: &ArgMatches,
    mut account_store: impl AccountStoreOperations,
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
    use clap::{ArgMatches, Command};
    use crate::account::tests::get_mock_store;

    const TOTP_KEY: &str = "NDVP6W4K6HKVUQJUY4F627PCSYUVQSNJF4BBTH2BQT24LONOLSXQ";

    pub struct MockOtpWriter {
        pub out: Vec<u8>,
        pub err: Vec<u8>,
    }

    impl MockOtpWriter {
        fn new() -> Self {
            MockOtpWriter {
                out: Vec::new(),
                err: Vec::new(),
            }
        }
    }

    impl OutErr for MockOtpWriter {
        fn write_err(&mut self, s: &str) {
            self.err = s.as_bytes().to_vec();
        }

        fn write(&mut self, s: &str) {
            self.out = s.as_bytes().to_vec();
        }
    }

    fn get_add_args(arg_vec: &Vec<&str>) -> Result<ArgMatches, clap::Error> {
        let matches = Command::new("otp")
            .subcommand(subcommand())
            .try_get_matches_from(arg_vec)?;

        let arg_matches = matches.subcommand().unwrap();
        let add_args = match arg_matches {
            ("add", add_args) => add_args.clone(),
            _ => panic!("Expected add subcommand"),
        };
        Ok(add_args)
    }

	#[test]
    fn adds_an_account() {
        let store = get_mock_store();
        let mut writer = MockOtpWriter::new();

        let arg_vec = vec!["otp", "add", "-a", "godaddy", "-k", TOTP_KEY];
        let add_args = get_add_args(&arg_vec).unwrap();

        run_add(&add_args, store, &mut writer);

        let expected_output = format!("Account \"{}\" successfully created", "godaddy");
        assert_eq!(writer.out, expected_output.as_bytes());
        assert_eq!(writer.err, Vec::new());
    }

    #[test]
    fn errors_if_account_exists() {
        let store = get_mock_store();
        let mut writer = MockOtpWriter::new();

        let arg_vec = vec!["otp", "add", "-a", "google", "-k", TOTP_KEY];
        let add_args = get_add_args(&arg_vec).unwrap();

        run_add(&add_args, store, &mut writer);

        assert_eq!(writer.err, "Account already exists\n".as_bytes());
        assert_eq!(writer.out, Vec::new());
    }

    #[test]
    fn validates_key_encoding() {
        let arg_vec = vec!["otp", "add", "-a", "google", "-k", "invalid-key!"];
        let add_args = get_add_args(&arg_vec);

        assert!(add_args.is_err());

        let err = add_args.unwrap_err();

        assert!(
            err.to_string()
                .contains("the key is not a valid base32 encoding"),
            "{}",
            err
        );
    }
}
