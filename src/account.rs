use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::io::{BufReader, Result};
use std::path::PathBuf;

use crate::utils::decrypt_pw;

const FILE_NAME: &str = "accounts.txt";

enum FileType {
    Accounts,
    Init,
}

fn get_path(file_type: FileType) -> Result<PathBuf> {
    let home = dirs::home_dir().expect("Unable to find home directory");
    let directory = home.join(".otp");
    fs::create_dir_all(&directory).expect("Unable to create .otp directory");

    let filename = match file_type {
        FileType::Accounts => FILE_NAME,
        FileType::Init => "init.txt",
    };

    Ok([directory, PathBuf::from(filename)].iter().collect())
}

fn load_file_to_string(path: &PathBuf) -> Result<String> {
    if !path.exists() {
        File::create(&path)?;
    }

    let file = File::open(path)?;
    let mut buf_reader = BufReader::new(file);
    let mut contents = String::new();
    buf_reader.read_to_string(&mut contents)?;
    Ok(contents)
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
    pin: Option<String>,
}

impl AccountStore {
    pub fn new() -> Result<AccountStore> {
        // Load Accounts
        let account_path = get_path(FileType::Accounts)?;
        let account_contents = load_file_to_string(&account_path)?;
        let accounts: BTreeMap<String, Account> = toml::from_str(&account_contents)?;

        // Load pin
        let pin_path = get_path(FileType::Init)?;
        let pin_contents = load_file_to_string(&pin_path)?;
        let pin: Option<String> = if pin_contents.is_empty() {
            None
        } else {
            Some(pin_contents)
        };

        Ok(AccountStore { accounts, pin })
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

    pub fn is_initialized(&self) -> bool {
        self.pin.is_some()
    }

    pub fn save(&self) -> Result<()> {
        let accounts_str = toml::to_string(&self.accounts).expect("Serialization failure");
        let path = get_path(FileType::Accounts)?;
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

    pub fn set_pin(&mut self, pin: &str) -> Result<()> {
        self.pin = Some(String::from(pin));
        let path = get_path(FileType::Init)?;
        if !path.exists() {
            File::create(&path)?;
        }
        fs::write(path, pin)?;
        Ok(())
    }

    pub fn validate_pin(&self, pin: &str) -> bool {
        let stored_pin = self.pin.clone().unwrap();
        let matches = decrypt_pw(&stored_pin, pin);
        matches
    }
}
