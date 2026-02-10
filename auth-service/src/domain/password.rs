use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
};
use color_eyre::eyre::{eyre, Context, Result};
use secrecy::{ExposeSecret, SecretString};

use crate::domain::UserStoreError;

#[derive(Debug, Clone)]
pub struct Password(SecretString); // updated!

impl PartialEq for Password {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl Password {
    #[tracing::instrument(name = "HashedPassword Parse", skip_all)]
    pub async fn parse(s: SecretString) -> Result<Self> {
        if !validate_password(&s) {
            return Err(eyre!("Failed to parse string to a HashedPassword type"));
        }
        let result = compute_password_hash(&s)
            .await
            .map_err(|e| UserStoreError::UnexpectedError(e.into()))?;

        Ok(Self(result))
    }

    #[tracing::instrument(name = "HashedPassword Parse password hash", skip_all)]
    pub fn parse_password_hash(hash: SecretString) -> Result<Self> {
        match PasswordHash::new(&hash.expose_secret()) {
            Ok(hashed_password) => Ok(Self(SecretString::new(
                hashed_password.to_string().into_boxed_str(),
            ))),
            Err(_) => return Err(eyre!("Failed to parse string to a HashedPassword type")),
        }
    }

    #[tracing::instrument(name = "Verify raw password", skip_all)]
    pub async fn verify_raw_password(&self, password_candidate: &SecretString) -> Result<()> {
        let current_span: tracing::Span = tracing::Span::current();

        let password_hash = self.as_ref().expose_secret().to_owned();
        let password_candidate = password_candidate.expose_secret().to_owned();

        tokio::task::spawn_blocking(move || {
            current_span.in_scope(|| {
                let expected_password_hash = PasswordHash::new(&password_hash)?;

                Argon2::default()
                    .verify_password(password_candidate.as_bytes(), &expected_password_hash)
                    .map_err(|e| e.into())
            })
        })
        .await?
    }
}

//..

// Helper function to hash passwords before persisting them in storage.
#[tracing::instrument(name = "Computing password hash", skip_all)]
async fn compute_password_hash(password: &SecretString) -> Result<SecretString> {
    let current_span = tracing::Span::current();
    let password = password.expose_secret().to_owned();

    let password_hash_res = tokio::task::spawn_blocking(move || {
        current_span.in_scope(|| {
            let salt: SaltString = SaltString::generate(&mut OsRng);
            let password_hash = Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                Params::new(15000, 2, 1, None)?,
            )
            .hash_password(password.as_bytes(), &salt)?
            .to_string();

            Ok(SecretString::new(password_hash.into_boxed_str()))
        })
    })
    .await?;

    password_hash_res
}

fn validate_password(s: &SecretString) -> bool {
    s.expose_secret().len() >= 8
}

//..

impl AsRef<SecretString> for Password {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Password;

    use fake::faker::internet::en::Password as FakePassword;
    use fake::Fake;
    use quickcheck::Gen;
    use rand::SeedableRng;
    use secrecy::SecretString; // New!

    #[tokio::test]
    async fn empty_string_is_rejected() {
        let password = SecretString::new("".to_string().into_boxed_str()); // Updated!
        assert!(Password::parse(password).await.is_err());
    }
    #[tokio::test]
    async fn string_less_than_8_characters_is_rejected() {
        let password = SecretString::new("1234567".to_owned().into_boxed_str()); // Updated!
        assert!(Password::parse(password).await.is_err());
    }

    #[derive(Debug, Clone)]
    struct ValidPasswordFixture(pub SecretString); // Updated!

    impl quickcheck::Arbitrary for ValidPasswordFixture {
        fn arbitrary(g: &mut Gen) -> Self {
            let seed: u64 = g.size() as u64;
            let mut rng = rand::rngs::SmallRng::seed_from_u64(seed);
            let password: String = FakePassword(8..30).fake_with_rng(&mut rng);
            Self(SecretString::new(password.into_boxed_str())) // Updated!
        }
    }
    #[tokio::test]
    #[quickcheck_macros::quickcheck]
    async fn valid_passwords_are_parsed_successfully(valid_password: ValidPasswordFixture) -> bool {
        Password::parse(valid_password.0).await.is_ok()
    }
}
