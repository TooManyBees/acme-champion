mod dns;
mod dns_handler;
mod http_handler;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::{net::TcpListener, signal::ctrl_c, sync::Mutex};

use dns_handler::{DnsStreamResult, bind_udp_stream, handle_dns, send_dns_response};
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

    let (mut dns_stream_4, mut dns_msg_rx_4) =
        bind_udp_stream(IpAddr::V4(Ipv4Addr::UNSPECIFIED), dns_port).await?;
    let (mut dns_stream_6, mut dns_msg_rx_6) =
        bind_udp_stream(IpAddr::V6(Ipv6Addr::UNSPECIFIED), dns_port).await?;

    tracing::info!("Listening for DNS traffic");

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
