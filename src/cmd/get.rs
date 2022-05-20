use clap::{arg, command, ArgMatches, Command};

use super::CommandType;
use crate::account::{AccountStoreOperations, OtpType};
use crate::hotp::get_hotp;
use crate::totp::{get_totp, get_totp_moving_factor, GetTime};
use crate::writer::OutErr;

pub fn subcommand() -> Command<'static> {
    command!(CommandType::Get.as_str())
        .about("Get a one-time password")
        .args(&[
            arg!(-a --account <NAME> "Account name to get one-time password for").required(true),
        ])
}

pub fn run_get<W>(
    get_args: &ArgMatches,
    account_store: &mut impl AccountStoreOperations,
    writer: &mut W,
    clock: &impl GetTime,
) where
    W: OutErr,
{
    let account_name = match get_args.value_of("account") {
        Some(account_name) => account_name,
        _ => {
            writer.write_err("Account name is required");
            return;
        }
    };

    let account = account_store.get(account_name);

    match account {
        None => writer.write_err(&format!("Account not found: {}\n", account_name)),
        Some(account) => {
            let (otp, new_counter) = match account.otp_type {
                OtpType::TOTP => (get_totp(&account.key, get_totp_moving_factor(clock)), None),
                OtpType::HOTP(maybe_counter) => {
                    let counter = maybe_counter.unwrap_or(0);
                    (get_hotp(&account.key, counter), Some(counter + 1))
                }
            };

            if new_counter.is_some() {
                account_store.set_counter(account_name, new_counter.unwrap_or(1));
            }

            match account_store.save() {
                Ok(_) => writer.write(&format!("{:0>6}\n", otp)),
                Err(err) => writer.write_err(&format!("Unable to save account: {}", err)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::tests::get_mock_store;
    use crate::cmd::CommandType::Get;
    use crate::tests::constants::*;
    use crate::tests::mocks::*;
    use crate::tests::utils::get_cmd_args;

    #[test]
    fn gets_totp_for_account() {
        let mut store = get_mock_store();
        let mut writer = MockOtpWriter::new();

        let arg_vec = vec!["otp", Get.as_str(), "-a", ACCOUNT_NAME_2];
        let get_args = get_cmd_args(CommandType::Get.as_str(), subcommand(), &arg_vec).unwrap();

        run_get(&get_args, &mut store, &mut writer, &MockClock::new());

        let expected_output = format!("583612\n");
        assert_eq!(String::from_utf8(writer.out).unwrap(), expected_output);
        assert_eq!(writer.err, Vec::new());
    }

    #[test]
    fn gets_hotp_for_account() {
        let mut store = get_mock_store();
        let mut writer = MockOtpWriter::new();

        let arg_vec = vec!["otp", Get.as_str(), "-a", ACCOUNT_NAME_1];
        let get_args = get_cmd_args(CommandType::Get.as_str(), subcommand(), &arg_vec).unwrap();

        run_get(&get_args, &mut store, &mut writer, &MockClock::new());

        let expected_output = format!("543440\n");
        assert_eq!(String::from_utf8(writer.out).unwrap(), expected_output);
        assert_eq!(writer.err, Vec::new());
    }

    #[test]
    #[should_panic]
    fn requires_account_name() {
        let arg_vec = vec!["otp", Get.as_str()];
        let get_args = get_cmd_args(CommandType::Get.as_str(), subcommand(), &arg_vec);

        assert!(get_args.is_err());

        let err = get_args.unwrap_err();

        assert!(
            err.to_string()
                .contains("the following required arguments were not provided: account"),
            "{}",
            err
        );
    }

    #[test]
    fn does_not_get_when_account_does_not_exist() {
        let mut store = get_mock_store();
        let mut writer = MockOtpWriter::new();

        let arg_vec = vec!["otp", Get.as_str(), "-a", "not_an_account"];
        let get_args = get_cmd_args(CommandType::Get.as_str(), subcommand(), &arg_vec).unwrap();

        run_get(&get_args, &mut store, &mut writer, &MockClock::new());

        let expected_output = format!("Account not found: {}\n", "not_an_account");
        assert_eq!(writer.out, Vec::new());
        assert_eq!(String::from_utf8(writer.err).unwrap(), expected_output);
    }

    #[test]
    fn increments_hotp_counter() {
        let mut store = get_mock_store();
        let mut writer = MockOtpWriter::new();

        let arg_vec = vec!["otp", Get.as_str(), "-a", ACCOUNT_NAME_1];
        let get_args = get_cmd_args(CommandType::Get.as_str(), subcommand(), &arg_vec).unwrap();

        run_get(&get_args, &mut store, &mut writer, &MockClock::new());

        let account = store.get(ACCOUNT_NAME_1).unwrap();
        let otp_type = &account.otp_type;
        assert_eq!(otp_type, &OtpType::HOTP(Some(1)));
        let expected_output = format!("543440\n");
        assert_eq!(String::from_utf8(writer.out).unwrap(), expected_output);
        assert_eq!(writer.err, Vec::new());

        let mut writer2 = MockOtpWriter::new();
        run_get(&get_args, &mut store, &mut writer2, &MockClock::new());

        let account = store.get(ACCOUNT_NAME_1).unwrap();
        let otp_type = &account.otp_type;
        assert_eq!(otp_type, &OtpType::HOTP(Some(2)));

        let expected_output = format!("119812\n");
        assert_eq!(String::from_utf8(writer2.out).unwrap(), expected_output);
        assert_eq!(writer2.err, Vec::new());

        let mut writer3 = MockOtpWriter::new();
        run_get(&get_args, &mut store, &mut writer3, &MockClock::new());

        let account = store.get(ACCOUNT_NAME_1).unwrap();
        let otp_type = &account.otp_type;
        assert_eq!(otp_type, &OtpType::HOTP(Some(3)));

        let expected_output = format!("307758\n");
        assert_eq!(String::from_utf8(writer3.out).unwrap(), expected_output);
        assert_eq!(writer3.err, Vec::new());
    }

    #[test]
    fn records_errors_on_save_failure() {
        let mut store = get_mock_store();
        let mut writer = MockOtpWriter::new();

        store.set_should_save_error(true);

        let arg_vec = vec!["otp", Get.as_str(), "-a", ACCOUNT_NAME_1];
        let get_args = get_cmd_args(Get.as_str(), subcommand(), &arg_vec).unwrap();

        run_get(&get_args, &mut store, &mut writer, &MockClock::new());

        assert_eq!(
            String::from_utf8(writer.err).unwrap(),
            "Unable to save account: MockAccountStore failed to save"
        );
        assert_eq!(writer.out, Vec::new());
    }
}
