use auth_service::Application;

#[tokio::main]
async fn main() {
    let address = "0.0.0.0:3000";
    let app = Application::build(address)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}


// AlexAlex2000A
// 142.93.254.141
// pirvate IP 10.116.0.2
