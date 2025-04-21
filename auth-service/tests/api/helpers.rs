use auth_service::Application;
use uuid::Uuid;

pub struct TestApp {
    pub address: String,
    pub http_client: reqwest::Client,
}

impl TestApp {
    pub async fn new() -> Self {
        let app = Application::build("127.0.0.1:0")
            .await
            .expect("Failed to build app");

        let address = format!("http://{}", app.address.clone());

        // Run the auth service in a separate async task
        // to avoid blocking the main test thread.
        #[allow(clippy::let_underscore_future)]
        let _ = tokio::spawn(app.run());

        let http_client = reqwest::Client::new(); // Create a Reqwest http client instance

        // Create new `TestApp` instance and return it
        TestApp {
            address,
            http_client,
        }
    }

    pub async fn get_root(&self) -> reqwest::Response {
        self.http_client
            .get(&format!("{}/", &self.address)) // TODO! Why &format?
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_login(&self, email: &str, password: &str) -> reqwest::Response {
        let params = [("email", email), ("password", password)];
        self.http_client
            .post(format!("{}/login", &self.address))
            .form(&params)
            .send()
            .await
            .expect("Failed to login")
    }

    pub async fn post_logout(&self) -> reqwest::Response {
        self.http_client
            .post(format!("{}/logout", &self.address))
            .send()
            .await
            .expect("Failed to logout")
    }

    pub async fn post_signup<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/signup", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to post a User")
    }

    pub async fn post_verify_2fa(
        &self,
        email: &str,
        login_attempt_id: &str,
        code: &str,
    ) -> reqwest::Response {
        let params = [
            ("email", email),
            ("loginAttemptId", login_attempt_id),
            ("2FACode", code),
        ];
        self.http_client
            .post(format!("{}/verify-2fa", &self.address))
            .form(&params)
            .send()
            .await
            .expect("Veirfying 2FA failed")
    }

    pub async fn post_verify_token(&self, token: &str) -> reqwest::Response {
        let params = [("token", token)];
        self.http_client
            .post(format!("{}/verify-token", &self.address))
            .form(&params)
            .send()
            .await
            .expect("Veirfying token failed")
    }
}

pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4())
}
