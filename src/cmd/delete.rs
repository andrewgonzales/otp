use clap::{arg, command, ArgMatches, Command};

use super::CommandType;
use crate::account::AccountStoreOperations;
use crate::writer::OutErr;

pub fn subcommand() -> Command<'static> {
    command!(CommandType::Delete.as_str())
        .about("Delete an account")
        .args(&[arg!(-a --account <NAME> "Account name to delete").required(true)])
}

pub fn run_delete<W>(
    delete_args: &ArgMatches,
    account_store: &mut impl AccountStoreOperations,
    writer: &mut W,
) where
    W: OutErr,
{
    let account_name = match delete_args.value_of("account") {
        Some(account_name) => account_name,
        _ => {
            writer.write_err("Account name is required\n");
            return;
        }
    };

    let result = account_store.delete(account_name);

    match result {
        Some(_) => match account_store.save() {
            Ok(_) => writer.write("Account successfully deleted\n"),
            Err(err) => writer.write_err(&format!("{}", err)),
        },
        None => writer.write_err(&format!("Account not found: {}\n", account_name)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::tests::get_mock_store;
    use crate::cmd::CommandType::Delete;
    use crate::tests::constants::*;
    use crate::tests::mocks::*;
    use crate::tests::utils::get_cmd_args;

    #[test]
    fn deletes_an_account() {
        let mut store = get_mock_store();
        let mut writer = MockOtpWriter::new();

        let arg_vec = vec!["otp", Delete.as_str(), "-a", ACCOUNT_NAME_1];
        let delete_args =
            get_cmd_args(CommandType::Delete.as_str(), subcommand(), &arg_vec).unwrap();

        run_delete(&delete_args, &mut store, &mut writer);

        assert_eq!(store.get(ACCOUNT_NAME_1), None);

        let expected_output = format!("Account successfully deleted\n");
        assert_eq!(String::from_utf8(writer.out).unwrap(), expected_output);
        assert_eq!(writer.err, Vec::new());
    }

    #[test]
    fn does_not_delete_an_account_that_does_not_exist() {
        let mut store = get_mock_store();
        let mut writer = MockOtpWriter::new();

        let arg_vec = vec!["otp", Delete.as_str(), "-a", "not_an_account"];
        let delete_args =
            get_cmd_args(CommandType::Delete.as_str(), subcommand(), &arg_vec).unwrap();

        run_delete(&delete_args, &mut store, &mut writer);

        let expected_output = format!("Account not found: {}\n", "not_an_account");
        assert_eq!(writer.out, Vec::new());
        assert_eq!(String::from_utf8(writer.err).unwrap(), expected_output);
    }

    #[test]
    fn requires_account_name() {
        let arg_vec = vec!["otp", Delete.as_str()];
        let delete_args = get_cmd_args(CommandType::Delete.as_str(), subcommand(), &arg_vec);

        assert!(delete_args.is_err());

        let err = delete_args.unwrap_err();

        assert!(err
            .to_string()
            .contains("The following required arguments were not provided:"));

        assert!(err.to_string().contains("--account <NAME>"));
    }

    #[test]
    fn records_errors_on_save_failure() {
        let mut store = get_mock_store();
        let mut writer = MockOtpWriter::new();

        store.set_should_save_error(true);

        let arg_vec = vec!["otp", Delete.as_str(), "-a", ACCOUNT_NAME_1];
        let delete_args = get_cmd_args(Delete.as_str(), subcommand(), &arg_vec).unwrap();

        run_delete(&delete_args, &mut store, &mut writer);

        assert_eq!(
            String::from_utf8(writer.err).unwrap(),
            "MockAccountStore failed to save"
        );
        assert_eq!(writer.out, Vec::new());
    }
}
