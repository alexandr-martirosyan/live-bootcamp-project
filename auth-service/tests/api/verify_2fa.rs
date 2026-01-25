use crate::helpers::TestApp;

#[tokio::test]
async fn verify_2fa_works_as_expected() {
    let app = TestApp::new().await;

    let response = app.post_varify_2fa().await;

    assert_eq!(response.status().as_u16(), 200);
}
