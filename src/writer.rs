use std::io::{self, Stderr, Stdout, Write};

pub struct OtpWriter {
    pub out: Stdout,
    pub err: Stderr,
}

impl OtpWriter {
    pub fn new() -> Self {
        OtpWriter {
            out: io::stdout(),
            err: io::stderr(),
        }
    }
}

pub trait OutErr {
    fn write_err(&mut self, s: &str);
    fn write(&mut self, s: &str);
}

impl OutErr for OtpWriter {
    fn write_err(&mut self, s: &str) {
        match self.err.write_all(s.as_bytes()) {
            Ok(_) => (),
            Err(e) => eprintln!("{}", e),
        }
    }

    fn write(&mut self, s: &str) {
        match self.out.write_all(s.as_bytes()) {
            Ok(_) => (),
            Err(e) => eprintln!("{}", e),
        }
    }
}
