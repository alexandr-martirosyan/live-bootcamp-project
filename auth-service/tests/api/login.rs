use crate::helpers::TestApp;

#[tokio::test]
pub async fn login_works() {
    let app = TestApp::new().await;

    let response = app.post_login("alexandr@gmail.com", "alexalex").await;

    assert_eq!(response.status().as_u16(), 200);
}

