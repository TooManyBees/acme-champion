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

use dns_handler::{handle_dns, make_dns_stream, DnsStreamResult};
use http_handler::handle_http;

#[derive(Debug)]
struct Challenges(Mutex<HashMap<String, String>>);

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    init_tracing();

    let http_addr = SocketAddr::from(([127, 0, 0, 1], 8053));
    let http_listener = TcpListener::bind(http_addr).await.map_err(|e| {
        tracing::error!(addr = %http_addr, error = %e, "Failed to bind TCP listener");
        e
    })?;
    tracing::debug!(addr = %http_addr, "Listening for TCP traffic");

    let dns_addr = SocketAddr::from(([0, 0, 0, 0], 5053));
    let dns_socket = UdpSocket::bind(dns_addr).await.map_err(|e| {
        tracing::error!(addr = %dns_addr, error = %e, "Failed to bind UDP listener");
        e
    })?;
    let (mut dns_stream, dns_handler) = make_dns_stream(dns_socket);
    tracing::debug!(addr = %dns_addr, "Listening for UDP traffic");

    let challenges = Arc::new(Challenges(Mutex::new(HashMap::new())));

    loop {
        tokio::select! {
            Ok((stream, _)) = http_listener.accept() => handle_http(stream, &challenges),
            next = dns_stream.next() => {
                match handle_dns(next, dns_handler.clone(), &challenges) {
                    DnsStreamResult::ConnectionBroken => break,
                    _ => {}
                }
            },
            _ = shutdown_signal() => {
                tracing::info!("Received shutdown signal");
                drop(http_listener);
                break;
            }
        }
    }

    tracing::info!("Shutting down");
    Ok(())
}

fn init_tracing() {
    use tracing::Level;
    use tracing_subscriber::{filter::Targets, prelude::*};
    let targets = Targets::new()
        .with_target("hyper", Level::INFO)
        .with_default(Level::DEBUG);
    let reg = tracing_subscriber::registry();
    let layer = tracing_subscriber::fmt::layer().pretty();
    reg.with(layer.with_filter(targets)).init();
}

async fn shutdown_signal() {
    ctrl_c().await.expect("failed to install signal handler");
}
