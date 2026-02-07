use std::collections::HashMap;

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

    async fn validate_user(&self, email: &Email, raw_password: &str) -> Result<(), UserStoreError> {
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
    use crate::domain::{Email, HashedPassword};

    async fn make_user(email: &str, password: &str) -> User {
        User::new(
            Email::parse(email.to_owned()).unwrap(),
            HashedPassword::parse(password.to_owned()).await.unwrap(),
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

        let u = store
            .get_user(&Email::parse("a@test.com".to_owned()).unwrap())
            .await
            .unwrap();
        assert_eq!(u.email(), &Email::parse("a@test.com".to_owned()).unwrap());

        let err = store
            .get_user(&Email::parse("missing@test.com".to_owned()).unwrap())
            .await
            .unwrap_err();
        assert_eq!(err, UserStoreError::UserNotFound);
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut store = HashMapUserStore::default();
        store
            .add_user(make_user("a@test.com", "password").await)
            .await
            .unwrap();

        assert!(store
            .validate_user(&Email::parse("a@test.com".to_owned()).unwrap(), "password")
            .await
            .is_ok());

        let err = store
            .validate_user(
                &Email::parse("a@test.com".to_owned()).unwrap(),
                "wrongpassword",
            )
            .await
            .unwrap_err();
        assert_eq!(err, UserStoreError::InvalidCredentials);

        let err = store
            .validate_user(
                &Email::parse("missing@test.com".to_owned()).unwrap(),
                "password",
            )
            .await
            .unwrap_err();
        assert_eq!(err, UserStoreError::UserNotFound);
    }
}
