use std::collections::HashSet;

use crate::domain::{BannedTokenStore, BannedTokenStoreError};

#[derive(Default)]
pub struct HashSetBannedTokenStore {
    users: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashSetBannedTokenStore {
    async fn ban_token(&mut self, token: &str) -> Result<(), BannedTokenStoreError> {
        self.users.insert(token.to_owned());
        Ok(())
    }
    async fn is_token_banned(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
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

        assert_eq!(store.is_token_banned(token).await.unwrap(), false);

        store.ban_token(token).await.unwrap();

        assert_eq!(store.is_token_banned(token).await.unwrap(), true);
    }

    #[tokio::test]
    async fn test_multiple_tokens() {
        let mut store = HashSetBannedTokenStore::default();
        let token1 = "token1";
        let token2 = "token2";

        store.ban_token(token1).await.unwrap();
        assert_eq!(store.is_token_banned(token1).await.unwrap(), true);
        assert_eq!(store.is_token_banned(token2).await.unwrap(), false);
    }
}
