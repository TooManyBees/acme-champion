mod http_handler;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::{
    net::TcpListener,
    signal::ctrl_c,
    sync::Mutex,
};

use http_handler::handle_http;

#[derive(Debug)]
struct Challenges(Mutex<HashMap<String, String>>);

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let http_addr = SocketAddr::from(([127, 0, 0, 1], 8053));
    let http_listener = TcpListener::bind(http_addr).await?;
    eprintln!("Listening for TCP traffic on 8053");

    let challenges = Arc::new(Challenges(Mutex::new(HashMap::new())));

    loop {
        tokio::select! {
            Ok((stream, _)) = http_listener.accept() => handle_http(stream, &challenges),
            _ = shutdown_signal() => {
                drop(http_listener);
                break;
            }
        }
    }

    eprintln!("bye!");
    Ok(())
}

async fn shutdown_signal() {
    ctrl_c().await.expect("failed to install signal handler");
}

