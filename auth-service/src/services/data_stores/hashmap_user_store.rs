use std::collections::HashMap;

use secrecy::SecretString;

use crate::domain::{Email, User, UserStore, UserStoreError};

#[derive(Default)]
pub struct HashMapUserStore {
    users: HashMap<Email, User>,
}

#[async_trait::async_trait]
impl UserStore for HashMapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        let email = user.email();

        if self.users.contains_key(&email) {
            Err(UserStoreError::UserAlreadyExists)
        } else {
            self.users.insert(email.clone(), user);
            Ok(())
        }
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        self.users
            .get(email)
            .cloned()
            .ok_or(UserStoreError::UserNotFound)
    }

    async fn validate_user(
        &self,
        email: &Email,
        raw_password: &SecretString,
    ) -> Result<(), UserStoreError> {
        let user = self.users.get(email).ok_or(UserStoreError::UserNotFound)?;

        user.password()
            .verify_raw_password(raw_password)
            .await
            .map_err(|_| UserStoreError::InvalidCredentials)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Email, Password};

    fn secret_str(s: &str) -> SecretString {
        // new
        SecretString::new(s.to_owned().into_boxed_str()) // new
    }

    fn create_email(s: &str) -> Email {
        // updated
        Email::parse(secret_str(s)).expect("valid email") // updated
    }

    async fn create_password(s: &str) -> Password {
        // new
        Password::parse(secret_str(s))
            .await
            .expect("valid password") // new
    }

    async fn make_user(email: &str, password: &str) -> User {
        User::new(
            create_email(email),             // updated
            create_password(password).await, // updated
            true,
        )
    }

    #[tokio::test]
    async fn test_add_user() {
        let mut store = HashMapUserStore::default();

        let u1 = make_user("a@test.com", "password1").await;
        assert!(store.add_user(u1).await.is_ok());

        let u2 = make_user("a@test.com", "password2").await;
        let err = store.add_user(u2).await.unwrap_err();
        assert_eq!(err, UserStoreError::UserAlreadyExists);
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut store = HashMapUserStore::default();
        store
            .add_user(make_user("a@test.com", "password").await)
            .await
            .unwrap();

        let email = create_email("a@test.com"); // new
        let u = store.get_user(&email).await.unwrap(); // updated
        assert_eq!(u.email(), &email); // updated

        let missing = create_email("missing@test.com"); // new
        let err = store.get_user(&missing).await.unwrap_err(); // updated
        assert_eq!(err, UserStoreError::UserNotFound);
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut store = HashMapUserStore::default();
        store
            .add_user(make_user("a@test.com", "password").await)
            .await
            .unwrap();

        let email = create_email("a@test.com"); // new

        assert!(store
            .validate_user(&email, &secret_str("password")) // updated
            .await
            .is_ok());

        let err = store
            .validate_user(&email, &secret_str("wrongpassword")) // updated
            .await
            .unwrap_err();
        assert_eq!(err, UserStoreError::InvalidCredentials);

        let missing = create_email("missing@test.com"); // new
        let err = store
            .validate_user(&missing, &secret_str("password")) // updated
            .await
            .unwrap_err();
        assert_eq!(err, UserStoreError::UserNotFound);
    }
}
