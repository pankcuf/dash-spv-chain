use std::time::SystemTime;

pub trait TimeUtil {
    fn seconds_since_1970() -> u64;
    // fn time_since
}

impl TimeUtil for SystemTime {
    fn seconds_since_1970() -> u64 {
        Self::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
    }
}


