use std::collections::HashSet;

use crate::domain::{BannedTokenStore, BannedTokenStoreError};

#[derive(Default)]
pub struct HashSetBannedTokenStore {
    users: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashSetBannedTokenStore {
    async fn add_token(&mut self, token: &str) -> Result<(), BannedTokenStoreError> {
        self.users.insert(token.to_owned());
        Ok(())
    }
    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        Ok(self.users.contains(token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::BannedTokenStore;

    #[tokio::test]
    async fn test_ban_and_check_token() {
        let mut store = HashSetBannedTokenStore::default();
        let token = "test_token";

        assert_eq!(store.contains_token(token).await.unwrap(), false);

        store.add_token(token).await.unwrap();

        assert_eq!(store.contains_token(token).await.unwrap(), true);
    }

    #[tokio::test]
    async fn test_multiple_tokens() {
        let mut store = HashSetBannedTokenStore::default();
        let token1 = "token1";
        let token2 = "token2";

        store.add_token(token1).await.unwrap();
        assert_eq!(store.contains_token(token1).await.unwrap(), true);
        assert_eq!(store.contains_token(token2).await.unwrap(), false);
    }
}
