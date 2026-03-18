mod dns;
mod dns_handler;
mod http_handler;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::{
    net::{TcpListener, UdpSocket},
    signal::ctrl_c,
    sync::Mutex,
};

use dns::{Message, UdpStream};
use dns_handler::{DnsStreamResult, handle_dns};
use http_handler::handle_http;

#[derive(Debug)]
struct Challenges(Mutex<HashMap<String, String>>);

fn main() {
    init_tracing();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();

    if let Err(e) = rt.block_on(main_loop()) {
        tracing::error!(error = %e);
    }

    tracing::info!("Shutting down");
}

async fn main_loop() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
    let (dns_stream, mut dns_msg_rx) = UdpStream::new(dns_socket);
    tracing::debug!(addr = %dns_addr, "Listening for UDP traffic");

    let challenges = Arc::new(Challenges(Mutex::new(HashMap::new())));

    let mut buf = [0u8; 512];
    loop {
        tokio::select! {
            Ok((stream, _)) = http_listener.accept() => handle_http(stream, &challenges),
            next = dns_stream.recv_from(&mut buf) => {
                match handle_dns(next, &challenges) {
                    DnsStreamResult::ConnectionBroken => break,
                    _ => {}
                }
            }
            msg = dns_msg_rx.recv() => {
                match msg {
                    Some(Message { data, addr }) => {
                        if let Err(e) = dns_stream.send_to(&data, addr).await {
                            tracing::error!(error = %e, addr = %addr, "error sending dns response");
                        }
                    }
                    None => {
                        tracing::error!("dns msg receiver unexpectedly closed");
                        break;
                    }
                }
            }
            _ = shutdown_signal() => {
                tracing::info!("Received shutdown signal");
                drop(http_listener);
                drop(dns_stream);
                break;
            }
        }
    }

    Ok(())
}

fn init_tracing() {
    use tracing::Level;
    use tracing_subscriber::{filter::Targets, prelude::*};
    let targets = Targets::new()
        .with_target("hyper", Level::INFO)
        .with_default(Level::TRACE);
    let reg = tracing_subscriber::registry();
    let layer = tracing_subscriber::fmt::layer().pretty();
    reg.with(layer.with_filter(targets)).init();
}

async fn shutdown_signal() {
    ctrl_c().await.expect("failed to install signal handler");
}
