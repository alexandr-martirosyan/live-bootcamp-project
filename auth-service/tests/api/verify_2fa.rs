use crate::helpers::{get_random_email, TestApp};
use auth_service::{
    domain::{Email, LoginAttemptId, TwoFACode},
    routes::TwoFactorAuthResponse,
    utils::constants::JWT_COOKIE_NAME,
    ErrorResponse,
};

#[tokio::test]
async fn should_return_200_if_correct_code() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    let response_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to LoginResponse");

    let expected_response_message = "2FA required".to_owned();
    assert_eq!(response_body.message, expected_response_message);

    let two_fa_code_store = app.two_fa_code_store.read().await;
    let code = two_fa_code_store
        .get_code(&Email::parse(random_email.to_owned()).unwrap())
        .await
        .expect("Could not get 2FA code from store");

    assert_eq!(response_body.login_attempt_id, code.0.as_ref().to_owned());

    let login_attempt_id = code.0.as_ref().to_owned();
    let two_fa_code = code.1.as_ref().to_owned();

    drop(two_fa_code_store);

    let verify_2fa_body = serde_json::json!({
        "email": random_email.as_str(),
        "loginAttemptId": login_attempt_id.as_str(),
        "2FACode": two_fa_code.as_str()
    });

    let response = app.post_verify_2fa(&verify_2fa_body).await;

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());

    assert_eq!(
        response.status().as_u16(),
        200,
        "Failed for input: {:?}",
        verify_2fa_body
    );

    let mut app = app;
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email(); // Call helper method to generate email

    let test_cases = [
        serde_json::json!({
            "email": random_email,
        }),
        serde_json::json!({
            "loginAttamptId": "Some String",
        }),
        serde_json::json!({
            "2FACode": "somecode"
        }),
        serde_json::json!({
            "email": random_email,
            "loginAttamptId": "Some String",
        }),
        serde_json::json!({
            "email": random_email,
            "2FACode": "somecode"
        }),
        serde_json::json!({
            "loginAttamptId": "Some String",
            "2FACode": "somecode"
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_verify_2fa(test_case).await; // call `post_signup`
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }

    let mut app = app;
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email();
    let login_attempt_id = LoginAttemptId::default().as_ref().to_owned();
    let two_fa_code = TwoFACode::default().as_ref().to_owned();

    let test_cases = [
        serde_json::json!({
            "email": "invalid_email",
            "loginAttemptId": login_attempt_id.as_str(),
            "2FACode": two_fa_code.as_str()
        }),
        serde_json::json!({
            "email": random_email.as_str(),
            "loginAttemptId": "invalid_login_attempt_id",
            "2FACode": two_fa_code.as_str()
        }),
        serde_json::json!({
            "email": random_email.as_str(),
            "loginAttemptId": login_attempt_id.as_str(),
            "2FACode": "invalid_two_fa_code"
        }),
        serde_json::json!({
            "email": "",
            "loginAttemptId": "",
            "2FACode": ""
        }),
    ];

    for test_case in test_cases {
        let response = app.post_verify_2fa(&test_case).await;

        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input: {:?}",
            test_case
        );

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Invalid credentials".to_owned()
        );
    }

    let mut app = app;
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    let response_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to LoginResponse");

    let expected_response_message = "2FA required".to_owned();
    assert_eq!(response_body.message, expected_response_message);

    let two_fa_code_store = app.two_fa_code_store.read().await;
    let code = two_fa_code_store
        .get_code(&Email::parse(random_email.to_owned()).unwrap())
        .await
        .expect("Could not get 2FA code from store");

    assert_eq!(response_body.login_attempt_id, code.0.as_ref().to_owned());

    let login_attempt_id = code.0.as_ref().to_owned();
    let two_fa_code = code.1.as_ref().to_owned();

    drop(two_fa_code_store);

    let incorrect_email = get_random_email();
    let incorrect_login_attempt_id = LoginAttemptId::default().as_ref().to_owned();
    let incorrect_two_fa_code = TwoFACode::default().as_ref().to_owned();

    let verify_2fa_bodies = [
        serde_json::json!({
            "email": incorrect_email.as_str(),
            "loginAttemptId": login_attempt_id.as_str(),
            "2FACode": two_fa_code.as_str()
        }),
        serde_json::json!({
            "email": random_email.as_str(),
            "loginAttemptId": incorrect_login_attempt_id.as_str(),
            "2FACode": two_fa_code.as_str()
        }),
        serde_json::json!({
            "email": random_email.as_str(),
            "loginAttemptId": login_attempt_id.as_str(),
            "2FACode": incorrect_two_fa_code.as_str()
        }),
    ];

    for verify_2fa_body in verify_2fa_bodies {
        let response = app.post_verify_2fa(&verify_2fa_body).await;

        assert_eq!(
            response.status().as_u16(),
            401,
            "Failed for input: \n{:?}",
            verify_2fa_body
        );

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Incorrect credentials".to_owned()
        );
    }

    let mut app = app;
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_old_code() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    let response_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to LoginResponse");

    let expected_response_message = "2FA required".to_owned();
    assert_eq!(response_body.message, expected_response_message);

    let two_fa_code_store = app.two_fa_code_store.read().await;
    let code = two_fa_code_store
        .get_code(&Email::parse(random_email.to_owned()).unwrap())
        .await
        .expect("Could not get 2FA code from store");

    assert_eq!(response_body.login_attempt_id, code.0.as_ref().to_owned());

    let old_two_fa_code = code.1.as_ref().to_owned();
    drop(two_fa_code_store);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    let two_fa_code_store = app.two_fa_code_store.read().await;
    let code = two_fa_code_store
        .get_code(&Email::parse(random_email.to_owned()).unwrap())
        .await
        .expect("Could not get 2FA code from store");

    let login_attempt_id = code.0.as_ref().to_owned();
    drop(two_fa_code_store);

    let verify_2fa_body = serde_json::json!({
        "email": random_email.as_str(),
        "loginAttemptId": login_attempt_id.as_str(),
        "2FACode": old_two_fa_code.as_str()
    });

    let response = app.post_verify_2fa(&verify_2fa_body).await;

    assert_eq!(
        response.status().as_u16(),
        401,
        "Failed for input: {:?}",
        verify_2fa_body
    );

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Incorrect credentials".to_owned()
    );

    let mut app = app;
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_same_code_twice() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    let response_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to LoginResponse");

    let expected_response_message = "2FA required".to_owned();
    assert_eq!(response_body.message, expected_response_message);

    let two_fa_code_store = app.two_fa_code_store.read().await;
    let code = two_fa_code_store
        .get_code(&Email::parse(random_email.to_owned()).unwrap())
        .await
        .expect("Could not get 2FA code from store");

    assert_eq!(response_body.login_attempt_id, code.0.as_ref().to_owned());

    let login_attempt_id = code.0.as_ref().to_owned();
    let two_fa_code = code.1.as_ref().to_owned();

    drop(two_fa_code_store);

    let verify_2fa_body = serde_json::json!({
        "email": random_email.as_str(),
        "loginAttemptId": login_attempt_id.as_str(),
        "2FACode": two_fa_code.as_str()
    });

    let response = app.post_verify_2fa(&verify_2fa_body).await;

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());

    assert_eq!(
        response.status().as_u16(),
        200,
        "Failed for input: {:?}",
        verify_2fa_body
    );

    let response = app.post_verify_2fa(&verify_2fa_body).await;

    assert_eq!(
        response.status().as_u16(),
        401,
        "Failed for input: {:?}",
        verify_2fa_body
    );

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Incorrect credentials".to_owned()
    );

    let mut app = app;
    app.clean_up().await;
}
