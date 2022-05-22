use std::io::{self, Stderr, Stdin, Stdout, Write};

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


pub struct OtpReader {
	pub input: Stdin,
}

impl OtpReader {
	pub fn new() -> Self {
		OtpReader {
			input: io::stdin(),
		}
	}
}

pub trait ReadLine {
	fn read_line(&mut self, b: &mut String) -> String;
}

impl ReadLine for OtpReader {
	fn read_line(&mut self, buffer: &mut String) -> String {
		match self.input.read_line(buffer) {
			Ok(_) => buffer.to_string(),
			Err(e) => {
				eprintln!("{}", e);
				String::new()
			}
		}
	}
}
