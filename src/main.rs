mod challenges;
mod config;
mod dns;
mod dns_handler;
mod http_handler;

use crate::challenges::Challenges;
use crate::config::{Config, ConfigError, parse_config, usage};
use crate::dns_handler::{bind_udp_socket, handle_dns};
use crate::http_handler::{bind_tcp_listener, handle_http};
use mio::net::{TcpListener, UdpSocket};
use mio::{Events, Interest, Poll, Token};
use std::io::ErrorKind;
use std::net::{SocketAddr, TcpStream};
use tracing::Level;

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

const TCP_LISTENER: Token = Token(0);
const UDP_SOCKET_4: Token = Token(1);
const UDP_SOCKET_6: Token = Token(2);

fn main_loop(config: Config) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut http_listener = bind_tcp_listener(config.http_port)?;
    let mut dns_socket_4 = bind_udp_socket(config.dns_addr_4)?;
    let mut dns_socket_6 = match bind_udp_socket(config.dns_addr_6) {
        Ok(maybe_socket) => maybe_socket,
        Err(e) => {
            if config.require_v6 {
                return Err(e.into());
            } else {
                None
            }
        }
    };
    tracing::info!("Listening");

    let mut challenges = Challenges::new();

    let mut poll = Poll::new()?;
    poll.registry()
        .register(&mut http_listener, TCP_LISTENER, Interest::READABLE)?;
    if let Some(ref mut socket) = dns_socket_4 {
        poll.registry()
            .register(socket, UDP_SOCKET_4, Interest::READABLE)?;
    }
    if let Some(ref mut socket) = dns_socket_6 {
        poll.registry()
            .register(socket, UDP_SOCKET_6, Interest::READABLE)?;
    }

    let mut events = Events::with_capacity(128);
    let mut buf = [0u8; 1024 * 4];
    loop {
        poll.poll(&mut events, None)?;

        for event in &events {
            if !event.is_readable() {
                continue;
            }

            match event.token() {
                TCP_LISTENER => {
                    while let Some(stream) = accept(&http_listener) {
                        if let Err(error) = handle_http(stream, &mut buf, &mut challenges) {
                            tracing::error!(%error, "Error handling HTTP request");
                        }
                    }
                }
                UDP_SOCKET_4 => {
                    if let Some(socket) = &dns_socket_4 {
                        while let Some((buf, addr)) = recv(&socket, &mut buf) {
                            handle_dns(buf, &socket, config.server_ips, addr, &challenges);
                        }
                    }
                }
                UDP_SOCKET_6 => {
                    if let Some(socket) = &dns_socket_6 {
                        while let Some((buf, addr)) = recv(&socket, &mut buf) {
                            handle_dns(buf, &socket, config.server_ips, addr, &challenges);
                        }
                    }
                }

                _ => {}
            }
        }
    }
}

fn accept(listener: &TcpListener) -> Option<TcpStream> {
    match listener.accept().and_then(|(stream, _addr)| {
        let stream: TcpStream = stream.into();
        stream.set_nonblocking(false).map(|_| stream)
    }) {
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
