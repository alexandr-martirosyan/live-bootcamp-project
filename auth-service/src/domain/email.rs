use color_eyre::eyre::{eyre, Result};
use validator::ValidateEmail;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Email(String);

impl Email {
    pub fn parse(email: String) -> Result<Email> {
        if email.validate_email() {
            Ok(Self(email))
        } else {
            Err(eyre!("{} is not a valid email.", email))
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
    use quickcheck::Gen;
    use rand::SeedableRng;

    #[test]
    fn valid_email_is_accepted() {
        let email_str: String = SafeEmail().fake();
        assert!(Email::parse(email_str.clone()).is_ok());
    }

    #[test]
    fn missing_at_symbol_is_rejected() {
        let email_str = "invalidemail.com".to_string();
        let err = Email::parse(email_str.clone()).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("{} is not a valid email.", email_str)
        );
    }

    #[test]
    fn invalid_email_is_rejected() {
        let email_str = "invalid@".to_string();
        let err = Email::parse(email_str.clone()).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("{} is not a valid email.", email_str)
        );
    }

    #[test]
    fn as_ref_returns_inner_str() {
        let email_str: String = SafeEmail().fake();
        let email = Email::parse(email_str.clone()).unwrap();
        assert_eq!(email.as_ref(), email_str.as_str());
    }

    #[derive(Debug, Clone)]
    struct ValidEmailFixture(pub String);

    impl quickcheck::Arbitrary for ValidEmailFixture {
        fn arbitrary(g: &mut Gen) -> Self {
            let seed: u64 = g.size() as u64;
            let mut rng = rand::rngs::SmallRng::seed_from_u64(seed);
            let email = SafeEmail().fake_with_rng(&mut rng);
            Self(email)
        }
    }

    #[quickcheck_macros::quickcheck]
    fn valid_emails_are_parsed_successfully(valid_email: ValidEmailFixture) -> bool {
        Email::parse(valid_email.0).is_ok()
    }
}
