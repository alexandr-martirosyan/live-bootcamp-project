use sqlx::PgPool;

use crate::domain::{Email, HashedPassword, User, UserStore, UserStoreError};

pub struct PostgresUserStore {
    pool: PgPool,
}

impl PostgresUserStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl UserStore for PostgresUserStore {
    #[tracing::instrument(name = "Adding user to PostgreSQL", skip_all)] // New!
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        let email = user.email().as_ref();
        let password_hash = user.password().as_ref();
        let requires_2fa = user.requires_2fa();

        let res = sqlx::query!(
            r#"
                INSERT INTO users (email, password_hash, requires_2fa)
                VALUES ($1, $2, $3)
            "#,
            email,
            password_hash,
            requires_2fa
        )
        .execute(&self.pool)
        .await;

        match res {
            Ok(_) => Ok(()),
            Err(e) => {
                if let Some(db_err) = e.as_database_error() {
                    if db_err.code().as_deref() == Some("23505") {
                        return Err(UserStoreError::UserAlreadyExists);
                    }
                }
                Err(UserStoreError::UnexpectedError)
            }
        }
    }

    #[tracing::instrument(name = "Retrieving user from PostgreSQL", skip_all)] // New!
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        let record = sqlx::query!(
            r#"
                SELECT email, password_hash, requires_2fa
                FROM users
                WHERE email = $1
            "#,
            email.as_ref(),
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| UserStoreError::UserNotFound)?;

        let email = Email::parse(record.email).map_err(|_| UserStoreError::UnexpectedError)?;
        let password = HashedPassword::parse_password_hash(record.password_hash)
            .map_err(|_| UserStoreError::UnexpectedError)?;
        let requires_2fa = record.requires_2fa;

        Ok(User::new(email, password, requires_2fa))
    }

    #[tracing::instrument(name = "Validating user credentials in PostgreSQL", skip_all)] // New!
    async fn validate_user(&self, email: &Email, raw_password: &str) -> Result<(), UserStoreError> {
        let user = self.get_user(email).await?;
        user.password()
            .verify_raw_password(raw_password)
            .await
            .map_err(|_| UserStoreError::InvalidCredentials)
    }
}
