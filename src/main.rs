mod challenges;
mod config;
mod dns;
mod dns_handler;
mod http_handler;

use std::io::ErrorKind;
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::time::Duration;
use tracing::Level;

use crate::challenges::{Challenge, Challenges};
use crate::config::{Config, ConfigError, parse_config, usage};
use crate::dns_handler::{bind_udp_socket, handle_dns};
use crate::http_handler::{bind_tcp_listener, handle_http};

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

    if let Err(error) = main_loop(config) {
        tracing::error!(%error);
    }

    tracing::info!("Shutting down");
}

const SLEEP: Duration = Duration::from_millis(100);

fn main_loop(config: Config) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let http_listener = bind_tcp_listener(config.http_port)?;
    let dns_socket_4 = bind_udp_socket(config.dns_addr_4)?;
    let dns_socket_6 = bind_udp_socket(config.dns_addr_6)?;
    tracing::info!("Listening");

    let mut challenges = Challenges::new();

    let mut tcp_buf = [0u8; 512];
    let mut udp_buf = [0u8; 512];
    loop {
        if let Some(stream) = accept(&http_listener) {
            if let Err(error) = handle_http(stream, &mut tcp_buf, &mut challenges) {
                tracing::error!(?error);
            }
        }

        if let Some(socket) = &dns_socket_4 {
            if let Some((buf, addr)) = recv(&socket, &mut udp_buf) {
                handle_dns(buf, &socket, addr, &challenges);
            }
        }

        if let Some(socket) = &dns_socket_6 {
            if let Some((buf, addr)) = recv(&socket, &mut udp_buf) {
                handle_dns(buf, &socket, addr, &challenges);
            }
        }

        std::thread::sleep(SLEEP);
    }
}

fn accept(listener: &TcpListener) -> Option<TcpStream> {
    match listener
        .accept()
        .and_then(|(stream, _addr)| stream.set_nonblocking(false).map(|_| stream))
    {
        Ok(stream) => Some(stream),
        Err(ref e) if e.kind() == ErrorKind::WouldBlock => None,
        Err(error) => {
            tracing::error!(%error, "Error receiving TCP connection");
            None
        }
    }
}

fn recv<'buf>(socket: &UdpSocket, buf: &'buf mut [u8]) -> Option<(&'buf [u8], SocketAddr)> {
    match socket.recv_from(buf) {
        Ok((n, addr)) => Some((&buf[..n], addr)),
        Err(ref e) if e.kind() == ErrorKind::WouldBlock => None,
        Err(error) => {
            tracing::error!(%error, "Error receiving UDP message");
            None
        }
    }
}

fn init_tracing(level: Level) {
    use tracing_subscriber::{filter::Targets, prelude::*};

    let targets = Targets::new().with_default(level);
    let reg = tracing_subscriber::registry();
    #[cfg(debug_assertions)]
    let layer = tracing_subscriber::fmt::layer().pretty();
    #[cfg(not(debug_assertions))]
    let layer = tracing_subscriber::fmt::layer().compact().with_ansi(false);
    reg.with(layer.with_filter(targets)).init();
}
