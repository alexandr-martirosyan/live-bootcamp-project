use std::collections::HashMap;

use crate::domain::{Email, Password, User, UserStore, UserStoreError};

#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<Email, User>,
}

#[async_trait::async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        match self.users.insert(user.email.clone(), user) {
            None => Ok(()),
            Some(_) => Err(UserStoreError::UserAlreadyExists),
        }
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        match self.users.get(email) {
            Some(user) => Ok(user.clone()),
            None => Err(UserStoreError::UserNotFound),
        }
    }

    async fn validate_user(
        &self,
        email: &Email,
        password: &Password,
    ) -> Result<(), UserStoreError> {
        if !self.get_user(email).await?.password.eq(password) {
            Err(UserStoreError::InvalidCredentials)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_user() {
        let mut user_store = HashmapUserStore::default();
        let email = Email::parse("alexandr@gmail.com").unwrap();
        let password = Password::parse("password").unwrap();
        let user = User::new(email, password, true);

        let res = user_store.add_user(user.clone()).await;
        assert!(res.is_ok());

        let res = user_store.add_user(user.clone()).await;
        assert_eq!(res, Err(UserStoreError::UserAlreadyExists));
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut user_store = HashmapUserStore::default();
        let email = Email::parse("alexandr@gmail.com").unwrap();
        let password = Password::parse("password").unwrap();
        let user = User::new(email, password, true);

        let res = user_store.get_user(&user.email).await;
        assert_eq!(res, Err(UserStoreError::UserNotFound));

        let _ = user_store.add_user(user.clone()).await;
        let res = user_store.get_user(&user.email).await;
        assert_eq!(res, Ok(user));
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut user_store = HashmapUserStore::default();
        let email = Email::parse("alexandr@gmail.com").unwrap();
        let password = Password::parse("password").unwrap();
        let user = User::new(email, password, true);

        let res = user_store.validate_user(&user.email, &user.password).await;
        assert_eq!(res, Err(UserStoreError::UserNotFound));

        // add user
        let _ = user_store.add_user(user.clone()).await;

        let res = user_store
            .validate_user(&user.email, &Password::parse("Wrong password").unwrap())
            .await;
        assert_eq!(res, Err(UserStoreError::InvalidCredentials));

        let res = user_store.validate_user(&user.email, &user.password).await;
        assert!(res.is_ok());
    }
}
