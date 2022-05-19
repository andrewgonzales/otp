use crate::writer::OutErr;

pub struct MockOtpWriter {
    pub out: Vec<u8>,
    pub err: Vec<u8>,
}

impl MockOtpWriter {
    pub fn new() -> Self {
        MockOtpWriter {
            out: Vec::new(),
            err: Vec::new(),
        }
    }
}

impl OutErr for MockOtpWriter {
    fn write_err(&mut self, s: &str) {
        self.err = s.as_bytes().to_vec();
    }

    fn write(&mut self, s: &str) {
        self.out = s.as_bytes().to_vec();
    }
}
