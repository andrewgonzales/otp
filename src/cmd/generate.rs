use clap::{arg, command, ArgMatches, Command};

use super::CommandType;
use crate::utils::{generate_secret, generate_secret_32};
use crate::writer::OutErr;

pub fn subcommand() -> Command<'static> {
    command!(CommandType::Generate.as_str())
        .about("Generate a Base32 secret key")
        .args(&[
            arg!(-c --counter "Key for counter-based HOTP (time-based TOTP is default)")
                .required(false),
        ])
}

pub fn run_generate<W>(generate_args: &ArgMatches, writer: &mut W)
where
    W: OutErr,
{
    let is_hotp = generate_args.is_present("counter");
    let new_secret_key = match is_hotp {
        true => generate_secret(),
        false => generate_secret_32(),
    };
    writer.write(&new_secret_key);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::CommandType::Generate;
    use crate::tests::constants::*;
    use crate::tests::mocks::MockOtpWriter;
    use crate::tests::utils::get_cmd_args;

    #[test]
    fn generates_a_20_byte_secret_for_hotp() {
        let mut writer = MockOtpWriter::new();

        let arg_vec = vec!["otp", Generate.as_str(), "-c"];
        let generate_args = get_cmd_args(Generate.as_str(), subcommand(), &arg_vec).unwrap();

        run_generate(&generate_args, &mut writer);

        assert_eq!(writer.out.len(), HOTP_KEY.as_bytes().len());
        assert_eq!(writer.err, Vec::new());
    }

    #[test]
    fn generates_a_32_byte_secret_for_totp() {
        let mut writer = MockOtpWriter::new();

        let arg_vec = vec!["otp", Generate.as_str()];
        let generate_args = get_cmd_args(Generate.as_str(), subcommand(), &arg_vec).unwrap();

        run_generate(&generate_args, &mut writer);

        assert_eq!(writer.out.len(), TOTP_KEY.as_bytes().len());
        assert_eq!(writer.err, Vec::new());
    }
}
