use auth_service::{routes::SignupResponse, ErrorResponse};

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email(); // Call helper method to generate email

    let test_cases = [
        serde_json::json!({
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email,
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email,
            "password": "password123",
        }),
        serde_json::json!({
            "email": random_email,
        }),
        serde_json::json!({
            "password": "password123",
        }),
        serde_json::json!({
            "requires2FA": true
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await; // call `post_signup`
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
async fn should_return_201_if_valid_input() {
    let app = TestApp::new().await;

    let user_json = serde_json::json!({
        "email": get_random_email(),
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_signup(&user_json).await; // call `post_signup`
    let expected_response = SignupResponse {
        message: "User created successfully!".to_owned(),
    };
    assert_eq!(
        response.status().as_u16(),
        201,
        "succeded for input: {:?}",
        user_json
    );
    assert_eq!(
        response
            .json::<SignupResponse>()
            .await
            .expect("Could not deserialize response body to UserBody"),
        expected_response
    );

    let mut app = app;
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email(); // Call helper method to generate email

    let test_cases = [
        // empty email
        serde_json::json!({
            "email": "",
            "password": "password123",
            "requires2FA": true
        }),
        // email without "@"
        serde_json::json!({
            "email": "some_email_atgmail.com",
            "password": "password123",
            "requires2FA": true
        }),
        // short password(< 8 chars)
        serde_json::json!({
            "email": random_email,
            "password": "passwd",
            "requires2FA": true
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await;
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
        )
    }

    let mut app = app;
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_409_if_email_already_exists() {
    // Call the signup route twice. The second request should fail with a 409 HTTP status code

    let app = TestApp::new().await;

    let user_json = serde_json::json!({
        "email": get_random_email(),
        "password": "password123",
        "requires2FA": true
    });
    let response = app.post_signup(&user_json).await; // call `post_signup`

    assert_eq!(
        response.status().as_u16(),
        201,
        "succeded for input: {:?}",
        user_json
    );

    let response = app.post_signup(&user_json).await; // call `post_signup`
    assert_eq!(
        response.status().as_u16(),
        409,
        "Failed for input: {:?}",
        user_json
    );
    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "User already exists".to_owned()
    );

    let mut app = app;
    app.clean_up().await;
}
