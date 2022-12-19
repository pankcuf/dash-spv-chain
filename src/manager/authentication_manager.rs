pub struct AuthenticationManager {
    pub did_authenticate: bool,
}

pub enum AuthenticationError {
    CannotCreateWallet,
    CannotRetrieveSeedFromKeychain,
    NotAuthenticated
}

impl AuthenticationManager {
    pub fn new() -> Self {
        Self { did_authenticate: false }
    }

    pub(crate) fn can_use_biometric_authentication_for_amount(&self, amount: u64) -> bool {
        todo!()
    }

    pub(crate) fn update_biometrics_amount_left_after_spending_amount(&self, amount: u64) -> bool {
        todo!()
    }

    pub async fn authenticate_with_prompt(&self, prompt: Option<String>, using_biometric_authentication: bool, alert_if_lockout: bool) -> Result<(bool, bool, bool), AuthenticationError> {
        todo!()
    }

}
