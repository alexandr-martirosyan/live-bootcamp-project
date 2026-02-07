use std::sync::Arc;

use redis::{Connection, TypedCommands};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::domain::{Email, LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError};

pub struct RedisTwoFACodeStore {
    connection: Arc<RwLock<Connection>>,
}

impl RedisTwoFACodeStore {
    pub fn new(connection: Arc<RwLock<Connection>>) -> Self {
        Self { connection }
    }
}

#[async_trait::async_trait]
impl TwoFACodeStore for RedisTwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(&email);
        let two_fa_info = TwoFATuple(
            login_attempt_id.as_ref().to_string(),
            code.as_ref().to_string(),
        );
        let two_fa_info = serde_json::to_string(&two_fa_info)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;

        self.connection
            .write()
            .await
            .set_ex(key, two_fa_info, TEN_MINUTES_IN_SECONDS)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(&email);
        let deleted: usize = self
            .connection
            .write()
            .await
            .del(key)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;
        match deleted {
            0 => Err(TwoFACodeStoreError::LoginAttemptIdNotFound),
            1 => Ok(()),
            _ => Err(TwoFACodeStoreError::UnexpectedError),
        }
    }

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        let key = get_key(&email);
        let two_fa_info = self
            .connection
            .write()
            .await
            .get(key)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?
            .ok_or(TwoFACodeStoreError::LoginAttemptIdNotFound)?;

        let two_fa_info: TwoFATuple = serde_json::from_str(two_fa_info.as_str())
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;
        let login_attempt_id = LoginAttemptId::parse(two_fa_info.0)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;
        let two_fa_code =
            TwoFACode::parse(two_fa_info.1).map_err(|_| TwoFACodeStoreError::UnexpectedError)?;

        Ok((login_attempt_id, two_fa_code))
    }
}

#[derive(Serialize, Deserialize)]
struct TwoFATuple(pub String, pub String);

const TEN_MINUTES_IN_SECONDS: u64 = 600;
const TWO_FA_CODE_PREFIX: &str = "two_fa_code:";

fn get_key(email: &Email) -> String {
    format!("{}{}", TWO_FA_CODE_PREFIX, email.as_ref())
}
