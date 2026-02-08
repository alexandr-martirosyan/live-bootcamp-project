use std::sync::Arc;

use redis::{Connection, TypedCommands};
use tokio::sync::RwLock;

use crate::{
    domain::{BannedTokenStore, BannedTokenStoreError},
    utils::auth::TOKEN_TTL_SECONDS,
};

pub struct RedisBannedTokenStore {
    connection: Arc<RwLock<Connection>>,
}

impl RedisBannedTokenStore {
    pub fn new(connection: Arc<RwLock<Connection>>) -> Self {
        Self { connection }
    }
}

#[async_trait::async_trait]
impl BannedTokenStore for RedisBannedTokenStore {
    async fn add_token(&mut self, token: &str) -> Result<(), BannedTokenStoreError> {
        let token_key = get_key(token);
        let value = true;

        let ttl: u64 = TOKEN_TTL_SECONDS
            .try_into()
            .map_err(|_| BannedTokenStoreError::UnexpectedError)?;

        let _: () = self
            .connection
            .write()
            .await
            .set_ex(&token_key, value, ttl)
            .map_err(|_| BannedTokenStoreError::UnexpectedError)?;

        Ok(())
    }

    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        // Check if the token exists by calling the exists method on the Redis connection
        let token_key = get_key(token);
        self.connection
            .write()
            .await
            .exists(&token_key)
            .map_err(|_| BannedTokenStoreError::UnexpectedError)
    }
}

// We are using a key prefix to prevent collisions and organize data!
const BANNED_TOKEN_KEY_PREFIX: &str = "banned_token:";

fn get_key(token: &str) -> String {
    format!("{}{}", BANNED_TOKEN_KEY_PREFIX, token)
}
