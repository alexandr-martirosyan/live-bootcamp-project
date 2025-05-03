use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, Password, User, UserStoreError},
};

pub async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let (email, password) = match (
        Email::parse(&request.email),
        Password::parse(&request.password),
    ) {
        (Ok(email), Ok(password)) => (email, password),
        _ => return Err(AuthAPIError::InvalidCredentials),
    };
    let user = User::new(email, password, request.requires_2fa);

    let mut user_store = state.user_store.write().await;

    match user_store.add_user(user).await {
        Err(UserStoreError::UserAlreadyExists) => Err(AuthAPIError::UserAlreadyExists),
        Err(_) => Err(AuthAPIError::UnexpectedError),
        _ => {
            let response = Json(SignupResponse {
                message: "User created successfully!".to_string(),
            });

            Ok((StatusCode::CREATED, response))
        }
    }
}

#[derive(Serialize, Debug, PartialEq, Deserialize)]
pub struct SignupResponse {
    pub message: String,
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}
