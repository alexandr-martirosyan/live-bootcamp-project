use validator::ValidateEmail;

use crate::domain::AuthAPIError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Email(String);

impl Email {
    pub fn parse(email: String) -> Result<Email, AuthAPIError> {
        if (&email).validate_email() {
            Ok(Email(email))
        } else {
            Err(AuthAPIError::InvalidCredentials)
        }
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fake::faker::internet::en::SafeEmail;
    use fake::Fake;
    use quickcheck_macros::quickcheck;
    use validator::ValidateEmail; // Needed for is_email()

    #[test]
    fn valid_email_is_accepted() {
        let email_str: String = SafeEmail().fake();
        assert!(Email::parse(email_str.clone()).is_ok());
    }

    #[test]
    fn missing_at_symbol_is_rejected() {
        let email_str = "invalidemail.com".to_string();
        let err = Email::parse(email_str).unwrap_err();
        assert_eq!(err, AuthAPIError::InvalidCredentials);
    }

    #[test]
    fn invalid_email_is_rejected() {
        let email_str = "invalid@".to_string();
        let err = Email::parse(email_str).unwrap_err();
        assert_eq!(err, AuthAPIError::InvalidCredentials);
    }

    #[test]
    fn as_ref_returns_inner_str() {
        let email_str: String = SafeEmail().fake();
        let email = Email::parse(email_str.clone()).unwrap();
        assert_eq!(email.as_ref(), email_str.as_str());
    }

    #[quickcheck]
    fn invalid_emails_are_rejected(input: String) -> bool {
        if input.validate_email() {
            Email::parse(input).is_ok()
        } else {
            Email::parse(input).is_err()
        }
    }
}
