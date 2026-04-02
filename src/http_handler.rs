use crate::challenges::{Challenge, Challenges};
use httparse::{Request, Status};
use std::fmt;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};

pub fn bind_tcp_listener(port: u16) -> std::io::Result<TcpListener> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let http_listener = TcpListener::bind(addr)
        .and_then(|listener| listener.set_nonblocking(true).map(|_| listener))
        .map_err(|error| {
            tracing::error!(%addr, %error, "Failed to bind TCP listener");
            error
        })?;
    tracing::debug!(%addr, "Listening for TCP traffic");
    Ok(http_listener)
}

#[derive(Debug)]
pub enum HttpError {
    Io(std::io::Error),
    Parse(httparse::Error),
}

impl From<std::io::Error> for HttpError {
    fn from(err: std::io::Error) -> HttpError {
        HttpError::Io(err)
    }
}

impl From<httparse::Error> for HttpError {
    fn from(err: httparse::Error) -> HttpError {
        HttpError::Parse(err)
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HttpError::Io(e) => e.fmt(fmt),
            HttpError::Parse(e) => e.fmt(fmt),
        }
    }
}

const REGISTER_PATH: &'static str = "/register/";

pub fn handle_http(
    mut stream: TcpStream,
    buf: &mut [u8],
    challenges: &mut Challenges,
) -> Result<(), HttpError> {
    let len = stream.read(buf)?;
    let mut http_headers = [httparse::EMPTY_HEADER; 8];
    let mut req = httparse::Request::new(&mut http_headers);
    let _body_offset = match req.parse(&buf[..len])? {
        Status::Complete(offset) => offset,
        Status::Partial => {
            empty_http_response(stream, 400, "bad request")?;
            return Ok(());
        }
    };

    let result = match (req.method, req.path) {
        (None, _) | (_, None) => empty_http_response(stream, 400, "bad request"),
        (Some("POST"), Some(path)) if path.starts_with(REGISTER_PATH) => {
            handle_set_challenge(stream, &req, challenges)
        }
        (Some("DELETE"), Some(path)) if path.starts_with(REGISTER_PATH) => {
            handle_unset_challenge(stream, &req, challenges)
        }
        (Some(_), Some(path)) if path.starts_with(REGISTER_PATH) => {
            empty_http_response(stream, 405, "method not allowed")
        }
        _ => empty_http_response(stream, 404, "not found"),
    };

    tracing::info!(
        method = %req.method.unwrap_or("unknown"),
        path = %req.path.unwrap_or("unknown"),
        "served http request",
    );

    if let Err(error) = result {
        tracing::error!(%error);
    }

    Ok(())
}

fn empty_http_response(
    mut stream: TcpStream,
    status_code: u16,
    reason: &str,
) -> std::io::Result<()> {
    stream.write_fmt(format_args!(
        "HTTP/1.1 {status_code} {reason}\r\nConnection: close\r\n\r\n"
    ))?;
    stream.flush()
}

fn handle_set_challenge(
    stream: TcpStream,
    req: &Request,
    challenges: &mut Challenges,
) -> std::io::Result<()> {
    let challenge = match challenge_from_req(req) {
        Ok(c) => c,
        Err(_) => return empty_http_response(stream, 400, "bad request"),
    };

    challenges.set(challenge.clone());
    tracing::info!(domain_name = %challenge.domain, challenge_name = %challenge.name, challenge_value = %challenge.value, "set challenge");
    empty_http_response(stream, 201, "created")
}

fn handle_unset_challenge(
    stream: TcpStream,
    req: &Request,
    challenges: &mut Challenges,
) -> std::io::Result<()> {
    let challenge = match challenge_from_req(req) {
        Ok(c) => c,
        Err(_) => return empty_http_response(stream, 400, "bad request"),
    };

    challenges.cleanup(&challenge);
    empty_http_response(stream, 204, "no content")
}

fn challenge_from_req(req: &Request) -> Result<Challenge, ()> {
    let domain = req
        .path
        .map(|p| &p[REGISTER_PATH.len()..])
        .ok_or(())?
        .trim_end_matches('.')
        .to_string();
    let name_header = match req
        .headers
        .iter()
        .find(|h| h.name == "X-ACME-Challenge-Name")
    {
        Some(header) => header.value,
        None => {
            tracing::warn!(domain_name = %domain, "ignoring HTTP request without X-ACME-Challenge-Name header");
            return Err(());
        }
    };
    let name = match String::from_utf8(name_header.to_vec()) {
        Ok(s) => s.trim_end_matches('.').to_string(),
        Err(_) => {
            tracing::warn!(domain_name = %domain, "ignoring HTTP request without non-visible ASCII challenge name");
            return Err(());
        }
    };
    let value_header = match req
        .headers
        .iter()
        .find(|h| h.name == "X-ACME-Challenge-Value")
    {
        Some(header) => header.value,
        None => {
            tracing::warn!(domain_name = %domain, challenge_name = %name, "ignoring HTTP request without X-ACME-Challenge-Value header");
            return Err(());
        }
    };
    let value = match String::from_utf8(value_header.to_vec()) {
        Ok(s) => s,
        Err(_) => {
            tracing::warn!(domain_name = %domain, challenge_name = %name, "ignoring HTTP request without non-visible ASCII challenge value");
            return Err(());
        }
    };

    Ok(Challenge {
        domain,
        name,
        value,
    })
}
