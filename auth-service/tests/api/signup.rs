use auth_service::routes::SignupResponse;

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_201_if_valid_input() {
    let app = TestApp::new().await;

    let rand_email = get_random_email();

    let test_case = serde_json::json!({
        "email": rand_email,
        "password": "password123",
        "requires2FA": true
    });

    let res = app.post_signup(&test_case).await;
    let expected_res = SignupResponse {
        message: "User created successfully!".to_owned(),
    };

    assert_eq!(res.status().as_u16(), 201);
    // Assert that we are getting the correct response body!
    assert_eq!(
        res.json::<SignupResponse>()
            .await
            .expect("Could not deserialize response body to UserBody"),
        expected_res
    );
}

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let rand_email = get_random_email();

    let test_cases = [
        serde_json::json!({
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": rand_email,
            "requires2FA": true
        }),
        serde_json::json!({
            "email": rand_email,
            "password": "password123",
        }),
        serde_json::json!({
            "email": rand_email,
            "password": "password123",
            "requires2FA": "true"
        }),
        serde_json::json!({}),
    ];

    for test_case in &test_cases {
        let res = app.post_signup(&test_cases).await;
        assert_eq!(
            res.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
}
