mod message;
mod node;
mod network;
mod session;
mod coordinator;

#[tokio::main]
async fn main() {
    env_logger::init();
    log::info!("MPC Node starting...");
    println!("MPC Node v0.1.0 — ready");
}