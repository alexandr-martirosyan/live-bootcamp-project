use crate::domain::AuthAPIError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Password(String);

impl Password {
    pub fn parse(password: String) -> Result<Password, AuthAPIError> {
        if password.len() >= 8 {
            Ok(Password(password))
        } else {
            Err(AuthAPIError::InvalidCredentials)
        }
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_password_is_accepted() {
        let password = "abcdefgh".to_string();
        assert!(Password::parse(password).is_ok());
    }

    #[test]
    fn short_password_is_rejected() {
        let password = "abc".to_string();
        let err = Password::parse(password).unwrap_err();
        assert_eq!(err, AuthAPIError::InvalidCredentials);
    }

    #[test]
    fn exactly_eight_characters_is_accepted() {
        let password = "12345678".to_string();
        assert!(Password::parse(password).is_ok());
    }

    #[test]
    fn empty_password_is_rejected() {
        let password = "".to_string();
        let err = Password::parse(password).unwrap_err();
        assert_eq!(err, AuthAPIError::InvalidCredentials);
    }
}
