#[derive(Clone, Debug, PartialEq)]
pub struct Password(String);

impl Password {
    pub fn parse(raw_pass: &str) -> Result<Password, String> {
        if validate_password(raw_pass) {
            Ok(Password(raw_pass.to_owned()))
        } else {
            Err(format!("Invalid Password: {}", raw_pass))
        }
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

fn validate_password(s: &str) -> bool {
    s.len() > 7
}

#[cfg(test)]
mod tests {
    use super::Password;

    use fake::{faker::internet::en::Password as FakePassword, Fake};

    #[test]
    fn empty_string_is_rejected() {
        let psswd = "";
        assert!(Password::parse(psswd).is_err());
    }

    #[test]
    fn short_password_is_rejected() {
        let psswd = "aleulom";
        assert!(Password::parse(psswd).is_err());
    }

    #[derive(Debug, Clone)]
    struct ValidPasswordFixture(pub String);

    impl quickcheck::Arbitrary for ValidPasswordFixture {
        fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Self {
            let psswd = FakePassword(8..20).fake_with_rng(g);
            Self(psswd)
        }
    }

    #[quickcheck_macros::quickcheck]
    fn valid_passwords_are_parsed_successfully(valid_psswd: ValidPasswordFixture) -> bool {
        Password::parse(&valid_psswd.0).is_ok()
    }
}
