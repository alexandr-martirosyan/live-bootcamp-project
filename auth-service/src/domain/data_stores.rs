use color_eyre::eyre::{eyre, Context, Report, Result};
use rand::Rng;
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;
use uuid::Uuid;

use crate::domain::Email;

use super::User;

#[async_trait::async_trait]
pub trait UserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError>;
    async fn validate_user(
        &self,
        email: &Email,
        raw_password: &SecretString,
    ) -> Result<(), UserStoreError>;
}

#[derive(Debug, Error)]
pub enum UserStoreError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for UserStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::UserAlreadyExists, Self::UserAlreadyExists)
                | (Self::UserNotFound, Self::UserNotFound)
                | (Self::InvalidCredentials, Self::InvalidCredentials)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[async_trait::async_trait]
pub trait BannedTokenStore {
    async fn add_token(&mut self, token: &SecretString) -> Result<(), BannedTokenStoreError>;
    async fn contains_token(&self, token: &SecretString) -> Result<bool, BannedTokenStoreError>;
}

#[derive(Debug, Error)]
pub enum BannedTokenStoreError {
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

// This trait represents the interface all concrete 2FA code stores should implement
#[async_trait::async_trait]
pub trait TwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError>;
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError>;
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError>;
}

#[derive(Debug, Error)]
pub enum TwoFACodeStoreError {
    #[error("Login Attempt ID not found")]
    LoginAttemptIdNotFound,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for TwoFACodeStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::LoginAttemptIdNotFound, Self::LoginAttemptIdNotFound)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[derive(Debug, Clone)]
pub struct LoginAttemptId(SecretString);

impl PartialEq for LoginAttemptId {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl AsRef<SecretString> for LoginAttemptId {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}

impl LoginAttemptId {
    pub fn parse(id: SecretString) -> Result<Self> {
        let parsed_id =
            Uuid::parse_str(&id.expose_secret()).wrap_err("Invalid login attempt id")?;
        Ok(Self(SecretString::new(
            parsed_id.to_string().into_boxed_str(),
        )))
    }
}

impl Default for LoginAttemptId {
    fn default() -> Self {
        Self(SecretString::new(
            Uuid::new_v4().to_string().into_boxed_str(),
        ))
    }
}

#[derive(Clone, Debug)]
pub struct TwoFACode(SecretString);

impl PartialEq for TwoFACode {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl AsRef<SecretString> for TwoFACode {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}

impl TwoFACode {
    pub fn parse(code: SecretString) -> Result<Self> {
        let code_str = code.expose_secret();
        // Ensure `code` is a valid 6-digit code
        if code_str.len() != 6 {
            return Err(eyre!("Invalid 2FA code"));
        }

        if !code_str.as_bytes().iter().all(|b| b.is_ascii_digit()) {
            return Err(eyre!("Invalid 2FA code"));
        }

        Ok(Self(code))
    }
}

impl Default for TwoFACode {
    fn default() -> Self {
        let n: u32 = rand::rng().random_range(0..1_000_000);
        Self(SecretString::new(format!("{:06}", n).into_boxed_str()))
    }
}
