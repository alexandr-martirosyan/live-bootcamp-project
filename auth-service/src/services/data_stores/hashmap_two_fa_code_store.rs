use std::collections::HashMap;

use crate::domain::{
    Email, {LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError},
};

#[derive(Default)]
pub struct HashMapTwoFACodeStore {
    codes: HashMap<Email, (LoginAttemptId, TwoFACode)>,
}

#[async_trait::async_trait]
impl TwoFACodeStore for HashMapTwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        self.codes.insert(email, (login_attempt_id, code));
        Ok(())
    }
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        self.codes
            .remove(email)
            .map(|_| ())
            .ok_or(TwoFACodeStoreError::LoginAttemptIdNotFound)
    }
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        self.codes
            .get(email)
            .cloned()
            .ok_or(TwoFACodeStoreError::LoginAttemptIdNotFound)
    }
}
#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::*;
    use crate::domain::{Email, LoginAttemptId, TwoFACode};

    fn test_email() -> Email {
        Email::parse(SecretString::new(
            "test@example.com".to_owned().into_boxed_str(),
        ))
        .unwrap()
    }

    fn test_login_attempt_id() -> LoginAttemptId {
        LoginAttemptId::default()
    }

    fn test_code() -> TwoFACode {
        TwoFACode::default()
    }

    #[tokio::test]
    async fn test_add_and_get_code() {
        let mut store = HashMapTwoFACodeStore::default();
        let email = test_email();
        let login_attempt_id = test_login_attempt_id();
        let code = test_code();

        store
            .add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await
            .unwrap();
        let (stored_id, stored_code) = store.get_code(&email).await.unwrap();

        assert_eq!(stored_id, login_attempt_id);
        assert_eq!(stored_code, code);
    }

    #[tokio::test]
    async fn test_remove_code() {
        let mut store = HashMapTwoFACodeStore::default();
        let email = test_email();
        let login_attempt_id = test_login_attempt_id();
        let code = test_code();

        store
            .add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await
            .unwrap();
        store.remove_code(&email).await.unwrap();
        let result = store.get_code(&email).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_remove_code_not_found() {
        let mut store = HashMapTwoFACodeStore::default();
        let email = test_email();

        let result = store.remove_code(&email).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_code_not_found() {
        let store = HashMapTwoFACodeStore::default();
        let email = test_email();

        let result = store.get_code(&email).await;
        assert!(result.is_err());
    }
}
