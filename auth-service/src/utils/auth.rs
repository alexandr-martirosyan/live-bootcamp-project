use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::Utc;
use color_eyre::eyre::{eyre, Context, ContextCompat, Result};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Validation};
use serde::{Deserialize, Serialize};

use crate::{app_state::BannedTokenStoreType, domain::Email};

use super::constants::{JWT_COOKIE_NAME, JWT_SECRET};

// Create cookie with a new JWT auth token
#[tracing::instrument(name = "auth:generate_auth_cookie", skip_all)] // New!
pub fn generate_auth_cookie(email: &Email) -> Result<Cookie<'static>> {
    let token = generate_auth_token(email)?;
    Ok(create_auth_cookie(token))
}

// Create cookie and set the value to the passed-in token string
#[tracing::instrument(name = "auth:create_auth_cookie", skip_all)] // New!
fn create_auth_cookie(token: String) -> Cookie<'static> {
    let cookie = Cookie::build((JWT_COOKIE_NAME, token))
        .path("/") // apply cookie to all URLs on the server
        .http_only(true) // prevent JavaScript from accessing the cookie
        .same_site(SameSite::Lax) // send cookie with "same-site" requests, and with "cross-site" top-level navigations.
        .build();

    cookie
}

// This value determines how long the JWT auth token is valid for
pub const TOKEN_TTL_SECONDS: i64 = 600; // 10 minutes

// Create JWT auth token
#[tracing::instrument(name = "auth:generate_auth_token", skip_all)] // New!
fn generate_auth_token(email: &Email) -> Result<String> {
    let delta = chrono::Duration::try_seconds(TOKEN_TTL_SECONDS)
        .wrap_err("failed to create 10 minute time delta")?;

    // Create JWT expiration time
    let exp = Utc::now()
        .checked_add_signed(delta)
        .ok_or(eyre!("failed to add 10 minutes to current time"))?
        .timestamp();

    // Cast exp to a usize, which is what Claims expects
    let exp: usize = exp.try_into().wrap_err(format!(
        "failed to cast exp time to usize. exp time: {}",
        exp
    ))?;

    let sub = email.as_ref().to_owned();

    let claims = Claims { sub, exp };

    create_token(&claims)
}

// Check if JWT auth token is valid by decoding it using the JWT secret
#[tracing::instrument(name = "auth:validate_token", skip_all)] // New!
pub async fn validate_token(
    token: &str,
    banned_token_store: BannedTokenStoreType,
) -> Result<Claims> {
    match banned_token_store.read().await.contains_token(token).await {
        Ok(value) => {
            if value {
                return Err(eyre!("token is banned"));
            }
        }
        Err(e) => return Err(e.into()),
    }

    decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .wrap_err("failed to decode token")
}

// Create JWT auth token by encoding claims using the JWT secret
#[tracing::instrument(name = "auth:create_token", skip_all)] // New!
fn create_token(claims: &Claims) -> Result<String> {
    encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
    .wrap_err("failed to create token")
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

#[cfg(test)]
mod tests {
    use crate::services::data_stores::HashSetBannedTokenStore;

    use super::*;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn empty_banned_store() -> BannedTokenStoreType {
        Arc::new(RwLock::new(HashSetBannedTokenStore::default()))
    }

    #[tokio::test]
    async fn test_generate_auth_cookie() {
        let email = Email::parse("test@example.com".to_owned()).unwrap();
        let cookie = generate_auth_cookie(&email).unwrap();
        assert_eq!(cookie.name(), JWT_COOKIE_NAME);
        assert_eq!(cookie.value().split('.').count(), 3);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_create_auth_cookie() {
        let token = "test_token".to_owned();
        let cookie = create_auth_cookie(token.clone());
        assert_eq!(cookie.name(), JWT_COOKIE_NAME);
        assert_eq!(cookie.value(), token);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_generate_auth_token() {
        let email = Email::parse("test@example.com".to_owned()).unwrap();
        let result = generate_auth_token(&email).unwrap();
        assert_eq!(result.split('.').count(), 3);
    }

    #[tokio::test]
    async fn test_validate_token_with_valid_token() {
        let email = Email::parse("test@example.com".to_owned()).unwrap();
        let token = generate_auth_token(&email).unwrap();

        let banned_token_store = empty_banned_store();

        let result = validate_token(&token, banned_token_store).await.unwrap();
        assert_eq!(result.sub, "test@example.com");

        let exp = Utc::now()
            .checked_add_signed(chrono::Duration::try_minutes(9).expect("valid duration"))
            .expect("valid timestamp")
            .timestamp();

        assert!(result.exp > exp as usize);
    }

    #[tokio::test]
    async fn test_validate_token_with_invalid_token() {
        let token = "invalid_token".to_owned();

        let banned_token_store = empty_banned_store();

        let result = validate_token(&token, banned_token_store).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_token_with_banned_token() {
        let email = Email::parse("test@example.com".to_owned()).unwrap();
        let token = generate_auth_token(&email).unwrap();

        let banned_token_store = empty_banned_store();

        // Mark token as banned using whatever method your store provides.
        // In your logout handler you called `.ban_token(token)`, so we mirror that.
        let mut store = banned_token_store.write().await;
        store
            .add_token(&token)
            .await
            .expect("failed to ban token in test");
        drop(store); // release the write lock

        let result = validate_token(&token, banned_token_store).await;
        assert!(result.is_err());
    }
}
