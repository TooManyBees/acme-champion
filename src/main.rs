mod dns;
mod dns_handler;
mod http_handler;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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

    let dns_port = 5053u16;

    let dns_addr_4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), dns_port);
    let dns_socket_4 = UdpSocket::bind(dns_addr_4).await.map_err(|e| {
        tracing::error!(addr = %dns_addr_4, error = %e, "Failed to bind UDP listener");
        e
    })?;
    let dns_addr_6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), dns_port);
    let dns_socket_6 = UdpSocket::bind(dns_addr_6).await.map_err(|e| {
        tracing::error!(addr = %dns_addr_4, error = %e, "Failed to bind UDP listener");
        e
    })?;
    let (mut dns_stream_4, mut dns_msg_rx_4) = UdpStream::new(dns_socket_4);
    tracing::debug!(addr = %dns_addr_4, "Listening for UDP traffic");
    let (mut dns_stream_6, mut dns_msg_rx_6) = UdpStream::new(dns_socket_6);
    tracing::debug!(addr = %dns_addr_6, "Listening for UDP traffic");

    let challenges = Arc::new(Challenges(Mutex::new(HashMap::new())));

    loop {
        tokio::select! {
            Ok((stream, _)) = http_listener.accept() => handle_http(stream, &challenges),
            next = dns_stream_4.recv_from() => {
                match handle_dns(next, &challenges) {
                    DnsStreamResult::ConnectionBroken => break,
                    _ => {}
                }
            }
            msg = dns_msg_rx_4.recv() => send_dns_response(&dns_stream_4, msg).await,
            next = dns_stream_6.recv_from() => {
                match handle_dns(next, &challenges) {
                    DnsStreamResult::ConnectionBroken => break,
                    _ => {}
                }
            }
            msg = dns_msg_rx_6.recv() => send_dns_response(&dns_stream_6, msg).await,
            _ = shutdown_signal() => {
                tracing::info!("Received shutdown signal");
                drop(http_listener);
                drop(dns_stream_4);
                drop(dns_stream_6);
                break;
            }
        }
    }

    Ok(())
}

async fn send_dns_response(stream: &UdpStream, message: Option<Message>) {
    match message {
        Some(Message { data, addr }) => {
            if let Err(e) = stream.send_to(&data, addr).await {
                tracing::error!(error = %e, addr = %addr, "error sending dns response");
            }
        }
        None => {
            tracing::error!("dns msg receiver unexpectedly closed");
        }
    }
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
