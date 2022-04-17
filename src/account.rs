use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::prelude::*;
use std::io::{BufReader, Result};
use std::path::PathBuf;

use crate::utils::{decrypt_pw, decrypt_string, encrypt_string};

const FILE_NAME: &str = "accounts.txt";
const SECRETS_FILE_NAME: &str = "secrets.txt";
enum FileType {
    Accounts,
    Secrets,
}

fn get_path(file_type: FileType) -> Result<PathBuf> {
    let home = dirs::home_dir().expect("Unable to find home directory");
    let directory = home.join(".otp");
    fs::create_dir_all(&directory).expect("Unable to create .otp directory");

    let filename = match file_type {
        FileType::Accounts => FILE_NAME,
        FileType::Secrets => SECRETS_FILE_NAME,
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

pub fn load_file_to_vec(path: &PathBuf) -> Result<Vec<u8>> {
    if !path.exists() {
        File::create(&path)?;
    }

    let file = File::open(path)?;
    let mut buf_reader = BufReader::new(file);
    let mut contents: Vec<u8> = Vec::new();
    buf_reader.read_to_end(&mut contents)?;

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

#[derive(Debug, Deserialize, Serialize)]
pub struct Secrets {
    pub pin: Option<String>,
    pub salt: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
}

pub struct AccountStore {
    accounts: BTreeMap<String, Account>,
    secrets: Secrets,
}

impl AccountStore {
    pub fn new() -> Result<AccountStore> {
        // Load secrets
        let secrets_path = get_path(FileType::Secrets)?;
        let secrets_content = load_file_to_string(&secrets_path)?;
        let secrets: Secrets = toml::from_str(&secrets_content)?;

        // Load Accounts
        let account_path = get_path(FileType::Accounts)?;

        let attempt = load_file_to_vec(&account_path);
        let encrypted_account_contents = match attempt {
            Ok(contents) => contents,
            Err(err) => {
                println!("oh no! {}", err);
                Vec::new()
            }
        };

        let account_contents = match encrypted_account_contents {
            contents if contents.is_empty() => String::from_utf8(contents).unwrap(),
            encrypted_contents => {
                let salt = secrets.salt.clone().unwrap();
                let nonce = secrets.nonce.clone().unwrap();
                let content = decrypt_string(&encrypted_contents, &salt, &nonce).unwrap();
                content
            }
        };

        let accounts: BTreeMap<String, Account> = toml::from_str(&account_contents)?;

        Ok(AccountStore { accounts, secrets })
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
        self.secrets.pin.is_some()
    }

    pub fn save(&self) -> Result<()> {
        let account_contents = toml::to_string(&self.accounts).expect("Serialization failure");
        let (encrypted_content, salt, nonce) = encrypt_string(&account_contents).unwrap();

        let path = get_path(FileType::Accounts)?;
        fs::write(path, encrypted_content)?;

        let secrets_path = get_path(FileType::Secrets)?;
        if !secrets_path.exists() {
            File::create(&secrets_path)?;
        }

        let secrets = Secrets {
            pin: self.secrets.pin.clone(),
            salt: Some(salt),
            nonce: Some(nonce),
        };

        let secrets_content = toml::to_string(&secrets).expect("Serialization failure");
        fs::write(secrets_path, secrets_content)?;

        Ok(())
    }

    pub fn set_counter(&mut self, account_name: &str, counter: i32) {
        let account = self.accounts.get_mut(account_name);
        match account {
            Some(account) => account.counter = Some(counter),
            None => println!("Account not found: {}", account_name),
        }
    }

    pub fn set_secrets(&mut self, pin: &str) -> Result<()> {
        self.secrets = Secrets {
            pin: Some(String::from(pin)),
            salt: None,
            nonce: None,
        };

        let secrets_contents = toml::to_string(&self.secrets).expect("Serialization failure");

        let secrets_path = get_path(FileType::Secrets)?;
        if !secrets_path.exists() {
            File::create(&secrets_path)?;
        }
        fs::write(secrets_path, &secrets_contents)?;

        Ok(())
    }

    pub fn validate_pin(&self, pin: &str) -> bool {
        let stored_pin = self.secrets.pin.clone().unwrap();
        let matches = decrypt_pw(&stored_pin, pin);
        matches
    }
}
