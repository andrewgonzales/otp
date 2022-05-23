## OTP

A command-line interface for generating counter-based (HOTP) and time-based (TOTP) one-time passwords based on [RFC 2226](https://datatracker.ietf.org/doc/html/rfc4226) and [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238). This was done as a means of learning Rust and some cryptography.

### Usage

1. `cargo build`
2. Add the cargo bin directory to your path in your shell environment, e.g.
```
# .zshrc

export PATH="$HOME/coding/otp/target/debug:$PATH"
```
3. run `otp -h` for a list of commands, and `otp <SUBCOMMAND> -h` for subcommand arguments.

```
otp v0.1.0
Time-based and counter-based one-time password generator

USAGE:
    otp <SUBCOMMAND>

OPTIONS:
    -h, --help       Print help information
    -V, --version    Print version information

SUBCOMMANDS:
    add         Add an account
    delete      Delete an account
    generate    Generate a Base32 secret key
    get         Get a one-time password
    help        Print this message or the help of the given subcommand(s)
    init        Initialize a new account store
    list        List all accounts
    validate    Validate a one-time password
```

```
$ otp init -p 5555
Client successfully initialized

$ otp generate
LFR5HZN2UUKIVJV7HZ3O3EPN4LPUVFM6GUL7FLKW22BQAL4JGD5A

$ otp add -a github -k LFR5HZN2UUKIVJV7HZ3O3EPN4LPUVFM6GUL7FLKW22BQAL4JGD5A
Enter your pin:
5555
Account "github" successfully created

$ otp list
Accounts:
github

$ otp get -a github
Enter your pin:
5555
680870

```
