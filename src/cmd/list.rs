use clap::{command, Command};

use super::CommandType;
use crate::account::AccountStoreOperations;
use crate::writer::OutErr;

pub fn subcommand() -> Command<'static> {
    command!(CommandType::List.as_str()).about("List all accounts")
}

pub fn run_list(account_store: &impl AccountStoreOperations, writer: &mut impl OutErr) {
    writer.write("Accounts:\n");
    for name in account_store.list() {
        writer.write(&format!("{}\n", name));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::tests::get_mock_store;
    use crate::tests::constants::*;
    use crate::tests::mocks::*;

    #[test]
    fn lists_account_names() {
        let mut store = get_mock_store();
        let mut writer = MockOtpWriter::new();

        run_list(&mut store, &mut writer);

        let expected_output = format!("Accounts:\n{}\n{}\n", ACCOUNT_NAME_1, ACCOUNT_NAME_2);
        assert_eq!(String::from_utf8(writer.out).unwrap(), expected_output);
        assert_eq!(writer.err, Vec::new());
    }
}
