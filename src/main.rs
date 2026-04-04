mod challenges;
mod config;
mod dns;
mod dns_handler;
mod http_handler;

use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::channel;
use tracing::Level;

use crate::challenges::{Challenge, Challenges};
use crate::config::{Config, ConfigError, parse_config, usage};
use crate::dns::Responder;
use crate::dns_handler::{bind_udp_stream, handle_dns};
use crate::http_handler::handle_http;

fn main() {
    let config = match parse_config() {
        Ok(c) => c,
        Err(error) => {
            match error {
                ConfigError::JustPrintUsage => eprintln!("{}", usage()),
                _ => {
                    init_tracing(Level::ERROR);
                    tracing::error!(%error, "Could not parse arguments");
                    eprintln!("{error}\n\n{}", usage());
                }
            }
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

    let challenges = Arc::new(Challenges::new());

    let (tx, mut rx) = channel(20);

    {
        let tx = tx.clone();
        tokio::task::spawn(async move {
            loop {
                let event = handle_tcp_connection(http_listener.accept().await);
                let _ = tx.send(event).await;
            }
        });
        tracing::debug!(addr = %http_addr, "Listening for TCP traffic");
    }

    if let Some(addr) = config.dns_addr_4 {
        let mut udp_stream = bind_udp_stream(addr).await?;
        let tx = tx.clone();
        tokio::task::spawn(async move {
            loop {
                let event = handle_udp_connection(udp_stream.next().await);
                let _ = tx.send(event).await;
            }
        });
        tracing::debug!(%addr, "Listening for UDP traffic");
    }

    if let Some(addr) = config.dns_addr_6 {
        match bind_udp_stream(addr).await {
            Ok(mut udp_stream) => {
                let tx = tx.clone();
                tokio::task::spawn(async move {
                    loop {
                        let event = handle_udp_connection(udp_stream.next().await);
                        let _ = tx.send(event).await;
                    }
                });
                tracing::debug!(%addr, "Listening for UDP traffic");
            }
            Err(e) => {
                if config.require_v6 {
                    return Err(e.into());
                }
            }
        }
    }

    tracing::info!("Started");

    while let Some(event) = rx.recv().await {
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

fn handle_tcp_connection(result: io::Result<(TcpStream, SocketAddr)>) -> LoopEvent {
    match result {
        Ok((stream, _)) => LoopEvent::NewHttpConn(stream),
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
