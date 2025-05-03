use validator::validate_email;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Email(String);

impl Email {
    pub fn parse(raw_email: &str) -> Result<Email, String> {
        if validate_email(raw_email) {
            Ok(Email(raw_email.to_owned()))
        } else {
            Err(format!("Invalid email: {}", raw_email))
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
    use super::Email;

    use fake::{faker::internet::en::SafeEmail, Fake};

    #[test]
    fn empty_string_is_rejected() {
        let email = "";
        assert!(Email::parse(email).is_err());
    }

    #[test]
    fn email_without_at_symbol_is_rejected() {
        let email = "alexgmail.com";
        assert!(Email::parse(email).is_err());
    }

    #[test]
    fn email_without_subject_is_rejected() {
        let email = "@gmail.com";
        assert!(Email::parse(email).is_err());
    }

    #[derive(Debug, Clone)]
    struct ValidEmailFixture(pub String);

    impl quickcheck::Arbitrary for ValidEmailFixture {
        fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Self {
            let email = SafeEmail().fake_with_rng(g);
            Self(email)
        }
    }

    #[quickcheck_macros::quickcheck]
    fn valid_emails_are_parsed_successfully(valid_email: ValidEmailFixture) -> bool {
        Email::parse(&valid_email.0).is_ok()
    }
}
