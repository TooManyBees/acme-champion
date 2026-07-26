mod challenges;
mod config;
mod dns;
mod dns_handler;
mod http_handler;
mod logger;
mod rate_limiter;
mod time;
mod user;

use crate::challenges::Challenges;
use crate::config::{Config, ConfigError, LogFormat, parse_config, usage};
use crate::dns_handler::{bind_udp_socket, handle_dns};
use crate::http_handler::{bind_tcp_listener, handle_http};
use crate::logger::init_logger;
use crate::rate_limiter::RateLimiter;
use crate::user::set_user;
use log::Level;
use mio::net::{TcpListener, UdpSocket};
use mio::{Events, Interest, Poll, Token};
use std::{
    error::Error,
    fmt,
    io::ErrorKind,
    net::{SocketAddr, TcpStream},
};

fn main() {
    let config = match parse_config() {
        Ok(c) => c,
        Err(error) => {
            match error {
                ConfigError::JustPrintUsage => eprintln!("{}", usage()),
                _ => {
                    _ = init_logger(Level::Error, LogFormat::default());
                    log::error!(error:% = error; "Could not parse arguments");
                    eprintln!("{error}\n\n{}", usage());
                }
            }
            std::process::exit(1);
        }
    };

    init_logger(config.loglevel, config.logformat);

    if let Err(error) = main_loop(config) {
        log::error!(error:% = error; "fatal error, shutting down");
    }
}

const TCP_LISTENER: Token = Token(0);
const UDP_SOCKET_4: Token = Token(1);
const UDP_SOCKET_6: Token = Token(2);

fn main_loop(config: Config) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut http_listener = bind_tcp_listener(config.http_port)?;
    let mut dns_socket_4 = bind_udp_socket(config.dns_addr_4, true)?;
    let mut dns_socket_6 = bind_udp_socket(config.dns_addr_6, config.require_v6)?;

    let mut challenges = Challenges::new();
    let mut rate_limiter = RateLimiter::new();

    let mut poll = Poll::new().map_err(|error| PollError {
        source: error,
        message: "could not create event poll",
    })?;
    poll.registry()
        .register(&mut http_listener, TCP_LISTENER, Interest::READABLE)
        .map_err(|error| PollError {
            source: error,
            message: "could not register TCP listener for wakeup events",
        })?;
    if let Some(ref mut socket) = dns_socket_4 {
        poll.registry()
            .register(socket, UDP_SOCKET_4, Interest::READABLE)
            .map_err(|error| PollError {
                source: error,
                message: "could not register UDP socket for wakeup events",
            })?;
    }
    if let Some(ref mut socket) = dns_socket_6 {
        poll.registry()
            .register(socket, UDP_SOCKET_6, Interest::READABLE)
            .map_err(|error| PollError {
                source: error,
                message: "could not register UDP socket for wakeup events",
            })?;
    }

    if let Some(username) = config.username {
        set_user(&username)?;
    }

    let mut events = Events::with_capacity(128);
    let mut buf = [0u8; 1024 * 4];
    loop {
        poll.poll(&mut events, None).map_err(|error| PollError {
            source: error,
            message: "could not poll IO events",
        })?;

        for event in &events {
            if !event.is_readable() {
                continue;
            }

            match event.token() {
                TCP_LISTENER => {
                    while let Some(stream) = accept(&http_listener) {
                        if let Err(error) = handle_http(stream, &mut buf, &mut challenges) {
                            log::error!(error:% = error; "Error handling HTTP request");
                        }
                    }
                }
                UDP_SOCKET_4 => {
                    if let Some(socket) = &dns_socket_4 {
                        while let Some((buf, addr)) = recv(&socket, &mut buf) {
                            handle_dns(
                                buf,
                                &socket,
                                config.server_ips,
                                addr,
                                &challenges,
                                &mut rate_limiter,
                            );
                        }
                    }
                }
                UDP_SOCKET_6 => {
                    if let Some(socket) = &dns_socket_6 {
                        while let Some((buf, addr)) = recv(&socket, &mut buf) {
                            handle_dns(
                                buf,
                                &socket,
                                config.server_ips,
                                addr,
                                &challenges,
                                &mut rate_limiter,
                            );
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
            log::error!(error:% = error; "Error receiving TCP connection");
            None
        }
    }
}

fn recv<'buf>(socket: &UdpSocket, buf: &'buf mut [u8]) -> Option<(&'buf [u8], SocketAddr)> {
    match socket.recv_from(buf) {
        Ok((n, addr)) => Some((&buf[..n], addr)),
        Err(ref e) if e.kind() == ErrorKind::WouldBlock => None,
        Err(error) => {
            log::error!(error:% = error; "Error receiving UDP message");
            None
        }
    }
}

#[derive(Debug)]
struct PollError {
    source: std::io::Error,
    message: &'static str,
}

impl fmt::Display for PollError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        self.message.fmt(fmt)
    }
}

impl Error for PollError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}
