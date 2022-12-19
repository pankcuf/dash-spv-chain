use crate::chain::chain::Chain;
use crate::platform::platform::Platform;

pub struct PlatformContext {
    pub platform: Platform,
}

impl PlatformContext {
    pub fn new(chain: &Chain) -> Self {
        Self {
            platform: Platform::new(chain)
        }
    }
}
