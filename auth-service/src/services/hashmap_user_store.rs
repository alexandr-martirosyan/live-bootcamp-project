use std::collections::HashMap;

use crate::domain::User;

#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError,
}

// TODO: Create a new struct called `HashmapUserStore` containing a `users` field
// which stores a `HashMap`` of email `String`s mapped to `User` objects.
// Derive the `Default` trait for `HashmapUserStore`.

#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<String, User>,
}

impl HashmapUserStore {
    pub fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        match self.users.insert(user.email.clone(), user) {
            None => Ok(()),
            Some(_) => Err(UserStoreError::UserAlreadyExists),
        }
    }

    pub fn get_user(&self, email: &str) -> Result<User, UserStoreError> {
        match self.users.get(email) {
            Some(user) => Ok(user.clone()),
            None => Err(UserStoreError::UserNotFound),
        }
    }

    pub fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError> {
        if !self.get_user(email)?.password.eq(password) {
            Err(UserStoreError::InvalidCredentials)
        } else {
            Ok(())
        }
    }
}

//  TODO: Add unit tests for your `HashmapUserStore` implementation
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_user() {
        let mut user_store = HashmapUserStore::default();
        let user = User::new("alexandr@gmail.com", "password", true);

        let res = user_store.add_user(user.clone());
        assert!(res.is_ok());

        let res = user_store.add_user(user.clone());
        assert_eq!(res, Err(UserStoreError::UserAlreadyExists));
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut user_store = HashmapUserStore::default();
        let user = User::new("alexandr@gmail.com", "password", true);

        let res = user_store.get_user(&user.email);
        assert_eq!(res, Err(UserStoreError::UserNotFound));

        let _ = user_store.add_user(user.clone());
        let res = user_store.get_user(&user.email);
        assert_eq!(res, Ok(user));
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut user_store = HashmapUserStore::default();
        let user = User::new("alexandr@gmail.com", "password", true);

        let res = user_store.validate_user(&user.email, &user.password);
        assert_eq!(res, Err(UserStoreError::UserNotFound));

        // add user
        let _ = user_store.add_user(user.clone());

        let res = user_store.validate_user(&user.email, "wrong password");
        assert_eq!(res, Err(UserStoreError::InvalidCredentials));

        let res = user_store.validate_user(&user.email, &user.password);
        assert!(res.is_ok());
    }
}
