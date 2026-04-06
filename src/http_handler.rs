use crate::challenges::{Challenge, Challenges};
use httparse::{Request, Status};
use mio::net::TcpListener;
use std::fmt;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};

pub fn bind_tcp_listener(port: u16) -> std::io::Result<TcpListener> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let http_listener = TcpListener::bind(addr).map_err(|error| {
        tracing::error!(%addr, %error, "Failed to bind TCP listener");
        error
    })?;
    tracing::info!(%addr, "Listening for TCP traffic");
    Ok(http_listener)
}

const REGISTER_PATH: &'static str = "/register/";

pub fn handle_http(
    mut stream: TcpStream,
    buf: &mut [u8],
    challenges: &mut Challenges,
) -> Result<(), HttpError> {
    let len = stream.read(buf).map_err(HttpError::Receive)?;
    let mut http_headers = [httparse::EMPTY_HEADER; 8];
    let mut req = httparse::Request::new(&mut http_headers);
    let _body_offset = match req.parse(&buf[..len]).map_err(HttpError::Parse)? {
        Status::Complete(offset) => offset,
        Status::Partial => {
            empty_http_response(stream, StatusCode::BAD_REQUEST).map_err(HttpError::Respond)?;
            return Ok(());
        }
    };

    let result = match (req.method, req.path) {
        (None, _) | (_, None) => empty_http_response(stream, StatusCode::BAD_REQUEST),
        (Some("GET"), Some("/")) => empty_http_response(stream, StatusCode::OK),
        (Some("POST"), Some(path)) if path.starts_with(REGISTER_PATH) => {
            handle_set_challenge(stream, &req, challenges)
        }
        (Some("DELETE"), Some(path)) if path.starts_with(REGISTER_PATH) => {
            handle_unset_challenge(stream, &req, challenges)
        }
        (Some(_), Some(path)) if path.starts_with(REGISTER_PATH) => {
            empty_http_response(stream, StatusCode::METHOD_NOT_ALLOWED)
        }
        _ => empty_http_response(stream, StatusCode::NOT_FOUND),
    };

    match result {
        Ok(status_code) => {
            tracing::info!(
                method = %req.method.unwrap_or("unknown"),
                path = %req.path.unwrap_or("unknown"),
                %status_code,
                "served http request",
            );
            Ok(())
        }
        Err(e) => Err(HttpError::Respond(e)),
    }
}

fn empty_http_response(
    mut stream: TcpStream,
    status_code: StatusCode,
) -> std::io::Result<StatusCode> {
    stream.write_fmt(format_args!(
        "HTTP/1.1 {} {}\r\nConnection: close\r\n\r\n",
        status_code.as_str(),
        status_code.reason(),
    ))?;
    stream.flush()?;
    Ok(status_code)
}

fn handle_set_challenge(
    stream: TcpStream,
    req: &Request,
    challenges: &mut Challenges,
) -> std::io::Result<StatusCode> {
    let challenge = match challenge_from_req(req) {
        Ok(c) => c,
        Err(_) => return empty_http_response(stream, StatusCode::BAD_REQUEST),
    };

    challenges.set(challenge.clone());
    tracing::info!(domain_name = %challenge.domain, challenge_name = %challenge.name, challenge_value = %challenge.value, "set challenge");
    empty_http_response(stream, StatusCode::CREATED)
}

fn handle_unset_challenge(
    stream: TcpStream,
    req: &Request,
    challenges: &mut Challenges,
) -> std::io::Result<StatusCode> {
    let challenge = match challenge_from_req(req) {
        Ok(c) => c,
        Err(_) => return empty_http_response(stream, StatusCode::BAD_REQUEST),
    };

    challenges.cleanup(&challenge);
    empty_http_response(stream, StatusCode::NO_CONTENT)
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

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug)]
enum StatusCode {
    OK,
    CREATED,
    NO_CONTENT,
    BAD_REQUEST,
    NOT_FOUND,
    METHOD_NOT_ALLOWED,
}

impl StatusCode {
    fn as_str(self) -> &'static str {
        use StatusCode::*;
        match self {
            OK => "200",
            CREATED => "201",
            NO_CONTENT => "204",
            BAD_REQUEST => "400",
            NOT_FOUND => "404",
            METHOD_NOT_ALLOWED => "405",
        }
    }

    fn reason(self) -> &'static str {
        use StatusCode::*;
        match self {
            OK => "Ok",
            CREATED => "Created",
            NO_CONTENT => "No Content",
            BAD_REQUEST => "Bad Request",
            NOT_FOUND => "Not Found",
            METHOD_NOT_ALLOWED => "Method Not Allowed",
        }
    }
}

impl fmt::Display for StatusCode {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{} {}", self.as_str(), self.reason())
    }
}

#[derive(Debug)]
pub enum HttpError {
    Receive(std::io::Error),
    Parse(httparse::Error),
    Respond(std::io::Error),
}

impl fmt::Display for HttpError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HttpError::Receive(e) => write!(fmt, "Error receiving HTTP request: {}", e),
            HttpError::Parse(e) => write!(fmt, "Error parsing HTTP request: {}", e),
            HttpError::Respond(e) => write!(fmt, "Error responding to HTTP request: {}", e),
        }
    }
}
