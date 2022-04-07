extern crate dirs;
extern crate toml;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::io::{BufReader, Result};
use std::path::PathBuf;

const FILE_PATH: &str = "accounts.txt";

fn get_path() -> Result<PathBuf> {
    let home = dirs::home_dir().expect("Unable to find home directory");
    let directory = home.join(".otp");
    fs::create_dir_all(&directory).expect("Unable to create .otp directory");

    Ok([directory, PathBuf::from(FILE_PATH)].iter().collect())
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Account {
    pub key: String,
    pub counter: Option<i32>,
}

impl Account {
    pub fn new(key: String) -> Self {
        Account {
            key,
            counter: Some(0),
        }
    }
}

pub struct AccountStore {
    accounts: BTreeMap<String, Account>,
}

impl AccountStore {
    pub fn new() -> Result<AccountStore> {
        let path = get_path()?;
        if !path.exists() {
            File::create(&path)?;
        }
        let file = File::open(path)?;
        let mut buf_reader = BufReader::new(file);
        let mut accounts_str = String::new();
        buf_reader.read_to_string(&mut accounts_str)?;
        let accounts: BTreeMap<String, Account> = toml::from_str(&accounts_str)?;
        Ok(AccountStore { accounts })
    }

    pub fn get(&self, account_name: &str) -> Option<&Account> {
        self.accounts.get(account_name)
    }

    pub fn list(&self) -> Vec<String> {
        self.accounts.keys().cloned().collect()
    }

    pub fn add(&mut self, account_name: String, account: Account) {
        self.accounts.insert(account_name, account);
    }

    pub fn delete(&mut self, account_name: &str) -> Option<Account> {
        self.accounts.remove(account_name)
    }

    pub fn save(&self) -> Result<()> {
        let accounts_str = toml::to_string(&self.accounts).expect("Serialization failure");
        let path = get_path()?;
        fs::write(path, accounts_str)?;
        Ok(())
    }

    pub fn set_counter(&mut self, account_name: &str, counter: i32) {
        let account = self.accounts.get_mut(account_name);
        match account {
            Some(account) => account.counter = Some(counter),
            None => println!("Account not found: {}", account_name),
        }
    }
}
