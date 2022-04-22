use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::prelude::*;
use std::io::{BufReader, Error, ErrorKind, Result};
use std::path::PathBuf;

use crate::crypto::{decrypt_pw, decrypt_string, encrypt_string};

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

fn decrypt_accounts(encrypted_account_contents: &Vec<u8>, secrets: &Secrets) -> Result<String> {
    match encrypted_account_contents {
        contents if contents.is_empty() => {
            let empty_string = String::from_utf8(contents.to_vec());
            match empty_string {
                Ok(empty_string) => return Ok(empty_string),
                Err(err) => return Err(Error::new(ErrorKind::InvalidData, err)),
            }
        }
        encrypted_contents => {
            let salt = secrets.get_salt();
            let nonce = secrets.nonce.clone();
            let decrypted_contents = match (salt, nonce) {
                (Some(salt), Some(nonce)) => {
                    let content = decrypt_string(&encrypted_contents, &salt, &nonce);

                    match content {
                        Ok(content) => Ok(content),
                        Err(_) => Err(Error::new(ErrorKind::InvalidData, "Decryption failed")),
                    }
                }
                _ => Err(Error::new(ErrorKind::InvalidData, "No salt or nonce found")),
            }?;

            return Ok(decrypted_contents);
        }
    };
}

fn deserialize_accounts(account_contents: String) -> Result<BTreeMap<String, Account>> {
    let accounts = toml::from_str(&account_contents);
    match accounts {
        Ok(accounts) => Ok(accounts),
        Err(err) => Err(Error::new(
            ErrorKind::InvalidData,
            format!("Deserialization failure: {}", err),
        )),
    }
}

fn load_accounts() -> Result<Vec<u8>> {
    let account_path = get_path(FileType::Accounts)?;

    let attempt = load_file_to_vec(&account_path);
    let encrypted_account_contents = match attempt {
        Ok(contents) => contents,
        Err(err) => {
            eprintln!("Error: {}", err);
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Oh no! Couldn't load the accounts",
            ));
        }
    };
    Ok(encrypted_account_contents)
}

fn load_secrets() -> Result<Secrets> {
    let secrets_path = get_path(FileType::Secrets)?;
    let secrets_content = load_file_to_string(&secrets_path)?;
    let secrets: Secrets = toml::from_str(&secrets_content)?;
    Ok(secrets)
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
struct Secrets {
    hash: Option<String>,
    nonce: Option<Vec<u8>>,
}

impl Secrets {
    fn get_salt(&self) -> Option<Vec<u8>> {
        let salt = match &self.hash {
            Some(hash) => {
                let salt = hash.clone().into_bytes()[..32].to_vec();
                Some(salt)
            }
            None => None,
        };
        salt
    }
}

pub struct AccountStore {
    accounts: BTreeMap<String, Account>,
    secrets: Secrets,
}

impl AccountStore {
    pub fn new() -> Result<AccountStore> {
        let secrets = load_secrets()?;
        let encrypted_account_contents = load_accounts()?;

        let account_contents = decrypt_accounts(&encrypted_account_contents, &secrets)?;
        let accounts = deserialize_accounts(account_contents)?;

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
        self.secrets.hash.is_some()
    }

    pub fn save(&self) -> Result<()> {
        // Encrypt and serialize accounts
        let account_contents = match toml::to_string(&self.accounts) {
            Ok(content) => content,
            Err(err) => {
                println!("Oh no! Couldn't save the accounts {}", err);
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "Account serialization failure",
                ));
            }
        };
        let salt = match self.secrets.get_salt() {
            Some(salt) => salt,
            None => {
                println!("No password found");
                return Err(Error::new(ErrorKind::InvalidData, "Missing salt"));
            }
        };
        let (encrypted_content, nonce) = match encrypt_string(&account_contents, &salt) {
            Ok(result) => result,
            Err(err) => {
                println!("Oh no! Couldn't save the accounts {}", err);
                return Err(Error::new(ErrorKind::InvalidData, "Encryption failure"));
            }
        };

        let path = get_path(FileType::Accounts)?;

        // Serialize secrets
        let secrets = Secrets {
            hash: self.secrets.hash.clone(),
            nonce: Some(nonce),
        };

        let secrets_content = match toml::to_string(&secrets) {
            Ok(content) => content,
            Err(err) => {
                println!("Oh no! Couldn't save {}", err);
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "Secrets serialization failure",
                ));
            }
        };

        // Save
        let secrets_path = get_path(FileType::Secrets)?;
        if !secrets_path.exists() {
            File::create(&secrets_path)?;
        }
        fs::write(secrets_path, secrets_content)?;
        fs::write(path, encrypted_content)?;

        Ok(())
    }

    pub fn set_counter(&mut self, account_name: &str, counter: i32) {
        let account = self.accounts.get_mut(account_name);
        match account {
            Some(account) => account.counter = Some(counter),
            None => println!("Account not found: {}", account_name),
        }
    }

    pub fn set_secrets(&mut self, hash: &str) -> Result<()> {
        self.secrets = Secrets {
            hash: Some(String::from(hash)),
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
        let stored_pin = match self.secrets.hash.clone() {
            Some(pin) => pin,
            None => return false,
        };
        let matches = decrypt_pw(&stored_pin, pin);
        matches
    }
}
