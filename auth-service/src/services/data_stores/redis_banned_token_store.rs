use std::sync::Arc;

use color_eyre::eyre::{eyre, Context};
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
    #[tracing::instrument(name = "RedisBannedTokenStore:add_token", skip_all)] // New!
    async fn add_token(&mut self, token: &str) -> Result<(), BannedTokenStoreError> {
        let token_key = get_key(token);
        let value = true;

        let ttl: u64 = TOKEN_TTL_SECONDS
            .try_into()
            .wrap_err("failed to cast TOKEN_TTL_SECONDS to u64") // New!
            .map_err(BannedTokenStoreError::UnexpectedError)?;

        let _: () = self
            .connection
            .write()
            .await
            .set_ex(&token_key, value, ttl)
            .wrap_err("failed to set banned token in Redis") // New!
            .map_err(BannedTokenStoreError::UnexpectedError)?;

        Ok(())
    }

    #[tracing::instrument(name = "RedisBannedTokenStore:contains_token", skip_all)] // New!
    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        // Check if the token exists by calling the exists method on the Redis connection
        let token_key = get_key(token);
        self.connection
            .write()
            .await
            .exists(&token_key)
            .wrap_err("failed to check if token exists in Redis") // New!
            .map_err(BannedTokenStoreError::UnexpectedError)
    }
}

// We are using a key prefix to prevent collisions and organize data!
const BANNED_TOKEN_KEY_PREFIX: &str = "banned_token:";

fn get_key(token: &str) -> String {
    format!("{}{}", BANNED_TOKEN_KEY_PREFIX, token)
}
