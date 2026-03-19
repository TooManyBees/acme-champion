mod config;
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
use tracing::Level;

use crate::config::{Config, parse_config};
use crate::dns::Responder;
use crate::dns_handler::{bind_udp_stream, handle_dns};
use crate::http_handler::handle_http;

#[derive(Debug)]
struct Challenges(Mutex<HashMap<String, String>>);

fn main() {
    let config = match parse_config() {
        Ok(c) => c,
        Err(e) => {
            let name = std::env::args()
                .next()
                .unwrap_or("acme-champion".to_string());
            eprintln!("{e}\n\nUsage:\n\t{name} [-p HTTP_PORT] [-l LOG_LEVEL]\n");
            std::process::exit(1);
        }
    };

    init_tracing(config.loglevel);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();

    if let Err(e) = rt.block_on(main_loop(config)) {
        tracing::error!(error = %e);
    }

    tracing::info!("Shutting down");
}

async fn main_loop(config: Config) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let http_addr = SocketAddr::from(([127, 0, 0, 1], config.http_port));
    let http_listener = TcpListener::bind(http_addr).await.map_err(|e| {
        tracing::error!(addr = %http_addr, error = %e, "Failed to bind TCP listener");
        e
    })?;
    let http_stream = TcpListenerStream::new(http_listener);
    tracing::debug!(addr = %http_addr, "Listening for TCP traffic");

    let dns_stream_4 = bind_udp_stream(IpAddr::V4(Ipv4Addr::UNSPECIFIED), config.dns_port).await?;
    let dns_stream_6 = bind_udp_stream(IpAddr::V6(Ipv6Addr::UNSPECIFIED), config.dns_port).await?;

    tracing::info!("Listening");

    let challenges = Arc::new(Challenges(Mutex::new(HashMap::new())));

    let stream = http_stream
        .map(handle_tcp_connection)
        .merge(dns_stream_4.map(handle_udp_connection))
        .merge(dns_stream_6.map(handle_udp_connection));
    let mut stream = pin!(stream);

    while let Some(event) = stream.next().await {
        match event {
            LoopEvent::NewHttpConn(stream) => handle_http(stream, &challenges),
            LoopEvent::NewUdpConn(msg, responder) => handle_dns(msg, responder, &challenges),
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

fn init_tracing(level: Level) {
    use tracing_subscriber::{filter::Targets, prelude::*};

    let targets = Targets::new()
        .with_target("hyper", Level::INFO)
        .with_default(level);
    let reg = tracing_subscriber::registry();
    #[cfg(debug_assertions)]
    let layer = tracing_subscriber::fmt::layer().pretty();
    #[cfg(not(debug_assertions))]
    let layer = tracing_subscriber::fmt::layer().compact().with_ansi(false);
    reg.with(layer.with_filter(targets)).init();
}
