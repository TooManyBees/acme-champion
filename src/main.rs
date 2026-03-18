mod dns;
mod dns_handler;
mod http_handler;

use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::pin;
use std::sync::Arc;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use tokio_stream::{StreamExt, wrappers::TcpListenerStream};

use crate::dns::Responder;
use dns_handler::{bind_udp_stream, handle_dns};
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
    let http_stream = TcpListenerStream::new(http_listener);
    tracing::debug!(addr = %http_addr, "Listening for TCP traffic");

    let dns_port = 5053u16;

    let dns_stream_4 = bind_udp_stream(IpAddr::V4(Ipv4Addr::UNSPECIFIED), dns_port).await?;
    let dns_stream_6 = bind_udp_stream(IpAddr::V6(Ipv6Addr::UNSPECIFIED), dns_port).await?;

    tracing::info!("Listening for DNS traffic");

    let challenges = Arc::new(Challenges(Mutex::new(HashMap::new())));

    let stream = http_stream
        .map(handle_tcp_connection)
        .merge(dns_stream_4.map(handle_udp_connection))
        .merge(dns_stream_6.map(handle_udp_connection));
    let mut stream = pin!(stream);

    while let Some(event) = stream.next().await {
        match event {
            LoopEvent::NewHttpConn(stream) => {
                handle_http(stream, &challenges);
            }
            LoopEvent::NewUdpConn(message, responder) => {
                handle_dns(message, responder, &challenges);
            }
            LoopEvent::NoOp => {}
            LoopEvent::Shutdown => break,
        }
    }

    Ok(())
}

enum LoopEvent {
    NewHttpConn(TcpStream),
    NewUdpConn(Vec<u8>, Responder),
    NoOp,
    Shutdown,
}

fn handle_tcp_connection(result: io::Result<TcpStream>) -> LoopEvent {
    match result {
        Ok(stream) => LoopEvent::NewHttpConn(stream),
        Err(e) => handle_io_error(e),
    }
}

fn handle_udp_connection(result: io::Result<(Vec<u8>, Responder)>) -> LoopEvent {
    match result {
        Ok((message, responder)) => LoopEvent::NewUdpConn(message, responder),
        Err(e) => handle_io_error(e),
    }
}

fn handle_io_error(error: io::Error) -> LoopEvent {
    match error.kind() {
        ErrorKind::NotConnected | ErrorKind::ConnectionAborted => {
            tracing::error!(%error);
            LoopEvent::Shutdown
        }
        _ => {
            tracing::warn!(%error);
            LoopEvent::NoOp
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
