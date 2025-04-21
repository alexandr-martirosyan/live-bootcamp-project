use crate::helpers::{get_random_email, TestApp};

// #[tokio::test]
// async fn signup_works() {
//     let app = TestApp::new().await;
//
//     let response = app.post_signup("alexandr@gmail.com", "alexalex", true).await;
//     assert_eq!(response.status().as_u16(), 200);
//     let response = app.post_signup("alexandr@gmail.com", "alexalex", false).await;
//     assert_eq!(response.status().as_u16(), 200);
// }

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
