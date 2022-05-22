use std::ops::Add;
use std::time::{Duration, SystemTime};

use crate::totp::GetTime;
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
        self.err.append(&mut s.as_bytes().to_vec());
    }

    fn write(&mut self, s: &str) {
        self.out.append(&mut s.as_bytes().to_vec());
    }
}

pub struct MockClock {}

impl MockClock {
    pub fn new() -> Self {
        MockClock {}
    }
}

impl GetTime for MockClock {
    fn get_now(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH.add(Duration::new(90, 0))
    }
}
