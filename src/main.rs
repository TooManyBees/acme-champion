mod dns_handler;
mod http_handler;

use futures_util::StreamExt;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::{
    net::{TcpListener, UdpSocket},
    signal::ctrl_c,
    sync::Mutex,
};

use dns_handler::{handle_dns, make_dns_stream};
use http_handler::handle_http;

#[derive(Debug)]
struct Challenges(Mutex<HashMap<String, String>>);

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let http_addr = SocketAddr::from(([127, 0, 0, 1], 8053));
    let http_listener = TcpListener::bind(http_addr).await?;
    eprintln!("Listening for TCP traffic on 8053");

    let dns_socket = UdpSocket::bind("0.0.0.0:5353").await?;
    let (mut dns_stream, dns_handler) = make_dns_stream(dns_socket);
    eprintln!("Listening for UDP traffic on 5353");

    let challenges = Arc::new(Challenges(Mutex::new(HashMap::new())));

    loop {
        tokio::select! {
            Ok((stream, _)) = http_listener.accept() => handle_http(stream, &challenges),
            next = dns_stream.next() => handle_dns(next, dns_handler.clone(), &challenges),
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
