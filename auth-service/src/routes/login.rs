use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, HashedPassword, LoginAttemptId, TwoFACode, UserStoreError},
    utils::generate_auth_cookie,
};

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let email = match Email::parse(request.email) {
        Ok(email) => email,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };
    let password = request.password;
    if HashedPassword::parse(password.clone()).await.is_err() {
        return (jar, Err(AuthAPIError::InvalidCredentials));
    };

    let user_store = state.user_store.read().await;

    match user_store.validate_user(&email, password.as_ref()).await {
        Ok(_) => (),
        Err(UserStoreError::UserNotFound | UserStoreError::InvalidCredentials) => {
            return (jar, Err(AuthAPIError::IncorrectCredentials));
        }
        Err(_) => return (jar, Err(AuthAPIError::UnexpectedError)),
    };
    let user = match user_store.get_user(&email).await {
        Ok(user) => user,
        Err(_) => return (jar, Err(AuthAPIError::IncorrectCredentials)),
    };

    if user.requires_2fa() {
        handle_2fa(user.email(), &state, jar).await
    } else {
        handle_no_2fa(&user.email(), jar).await
    }
}

async fn handle_2fa(
    email: &Email,
    state: &AppState,
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    // First, we must generate a new random login attempt ID and 2FA code
    let two_fa_code = TwoFACode::default();
    let login_attempt_id = LoginAttemptId::default();
    let login_attampt_id_str = login_attempt_id.as_ref().to_owned();

    if state
        .email_client
        .read()
        .await
        .send_email(
            email,
            "Your 2FA Code",
            &format!("Your 2FA code is: {}", two_fa_code.as_ref()),
        )
        .await
        .is_err()
    {
        return (jar, Err(AuthAPIError::UnexpectedError));
    };

    if state
        .two_fa_code_store
        .write()
        .await
        .add_code(email.clone(), login_attempt_id, two_fa_code)
        .await
        .is_err()
    {
        return (jar, Err(AuthAPIError::UnexpectedError));
    }

    let two_factor_auth_res = Json(LoginResponse::TwoFactorAuth(TwoFactorAuthResponse {
        message: "2FA required".to_owned(),
        login_attempt_id: login_attampt_id_str,
    }));
    (jar, Ok((StatusCode::PARTIAL_CONTENT, two_factor_auth_res)))
}

async fn handle_no_2fa(
    email: &Email,
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    let auth_cookie = match generate_auth_cookie(email) {
        Ok(cookie) => cookie,
        Err(_) => return (jar, Err(AuthAPIError::UnexpectedError)),
    };

    let updated_jar = jar.add(auth_cookie);

    let regular_auth_res = Json(LoginResponse::RegularAuth);
    (updated_jar, Ok((StatusCode::OK, regular_auth_res)))
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

// The login route can return 2 possible success responses.
// This enum models each response!
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum LoginResponse {
    RegularAuth,
    TwoFactorAuth(TwoFactorAuthResponse),
}

// If a user requires 2FA, this JSON body should be returned!
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct TwoFactorAuthResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
}
