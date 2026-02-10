use std::collections::HashSet;

use secrecy::{ExposeSecret, SecretString};

use crate::domain::{BannedTokenStore, BannedTokenStoreError};

#[derive(Default)]
pub struct HashSetBannedTokenStore {
    users: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashSetBannedTokenStore {
    async fn add_token(&mut self, token: &SecretString) -> Result<(), BannedTokenStoreError> {
        self.users.insert(token.expose_secret().to_owned());
        Ok(())
    }
    async fn contains_token(&self, token: &SecretString) -> Result<bool, BannedTokenStoreError> {
        Ok(self.users.contains(token.expose_secret()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::BannedTokenStore;

    #[tokio::test]
    async fn test_ban_and_check_token() {
        let mut store = HashSetBannedTokenStore::default();
        let token = SecretString::new("test_token".to_owned().into_boxed_str());

        assert_eq!(store.contains_token(&token).await.unwrap(), false);

        store.add_token(&token).await.unwrap();

        assert_eq!(store.contains_token(&token).await.unwrap(), true);
    }

    #[tokio::test]
    async fn test_multiple_tokens() {
        let mut store = HashSetBannedTokenStore::default();
        let token1 = SecretString::new("token1".to_owned().into_boxed_str());
        let token2 = SecretString::new("token2".to_owned().into_boxed_str());

        store.add_token(&token1).await.unwrap();
        assert_eq!(store.contains_token(&token1).await.unwrap(), true);
        assert_eq!(store.contains_token(&token2).await.unwrap(), false);
    }
}
