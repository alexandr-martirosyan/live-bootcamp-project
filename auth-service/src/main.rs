use std::sync::Arc;

use auth_service::{
    app_state::AppState, services::hashmap_user_store::HashmapUserStore, Application,
};
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let user_store = Arc::new(RwLock::new(HashmapUserStore::default()));
    let app_state = AppState::new(user_store);

    let address = "0.0.0.0:3000";
    let app = Application::build(app_state, address)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}

// AlexAlex2000A
// 142.93.254.141
// pirvate IP 10.116.0.2
