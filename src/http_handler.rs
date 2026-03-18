use super::Challenges;

use std::pin::Pin;
use std::sync::Arc;

use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Bytes, Incoming},
    server::conn::http1,
    service::Service,
};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

type HyperBodyResponse = Response<BoxBody<Bytes, hyper::Error>>;
type HyperResponseResult = Result<HyperBodyResponse, hyper::Error>;

pub fn handle_http(stream: TcpStream, challenges: &Arc<Challenges>) {
    let service = ChallengeRegister::new(challenges.clone());
    let io = TokioIo::new(stream);
    tokio::task::spawn(async move {
        if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
            tracing::error!(error = %err, "error serving TCP connection");
        }
    });
}

#[derive(Clone, Debug)]
struct ChallengeRegister {
    challenges: Arc<Challenges>,
}

impl ChallengeRegister {
    fn new(challenges: Arc<Challenges>) -> Self {
        ChallengeRegister { challenges }
    }
}

const REGISTER_PATH: &'static str = "/register/";

impl Service<Request<Incoming>> for ChallengeRegister {
    type Response = Response<BoxBody<Bytes, hyper::Error>>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let challenges = self.challenges.clone();
        Box::pin(async {
            let path = req.uri().path().to_string();
            let method = req.method().clone();
            let status_code;
            let resp = match (req.method(), req.uri().path()) {
                (&Method::GET, "/") => handle_get_challenges(challenges).await,
                (_, "/") => Ok(empty_response(StatusCode::METHOD_NOT_ALLOWED)),
                (&Method::POST, path) if path.starts_with(REGISTER_PATH) => {
                    handle_set_challenge(req, challenges).await
                }
                (&Method::DELETE, path) if path.starts_with(REGISTER_PATH) => {
                    handle_unset_challenge(req, challenges).await
                }
                (_, path) if path.starts_with(REGISTER_PATH) => Ok(empty_response(StatusCode::METHOD_NOT_ALLOWED)),
                _ => Ok(empty_response(StatusCode::NOT_FOUND)),
            };
            let resp = match resp {
                Ok(resp) => {
                    status_code = resp.status();
                    Ok(resp)
                }
                Err(e) => {
                    status_code = StatusCode::INTERNAL_SERVER_ERROR;
                    tracing::error!(error = %e);
                    Ok(empty_response(StatusCode::INTERNAL_SERVER_ERROR))
                }
            };
            tracing::info!(
                method = %method,
                path = %path,
                status_code = %status_code.as_u16(),
                "served HTTP request",
            );
            resp
        })
    }
}

async fn handle_get_challenges(challenges: Arc<Challenges>) -> HyperResponseResult {
    let challenges = challenges.0.lock().await;
    let mut result = String::new();
    for (key, value) in challenges.iter() {
        result.push_str(key);
        result.push(' ');
        result.push_str(value);
        result.push('\n');
    }
    Ok(full_response(StatusCode::OK, result))
}

async fn handle_set_challenge(
    req: Request<Incoming>,
    challenges: Arc<Challenges>,
) -> HyperResponseResult {
    let challenge_name = req.uri().path()[REGISTER_PATH.len()..].to_string();
    let challenge_header = match req.headers().get("X-ACME-Challenge-Value") {
        Some(value) => value,
        None => {
            tracing::warn!(%challenge_name, "ignoring HTTP request without X-ACME-Challenge-Value header");
            return Ok(empty_response(StatusCode::BAD_REQUEST));
        }
    };
    let challenge_value = match challenge_header.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            tracing::warn!(%challenge_name, "ignoring HTTP request without non-visible ASCII challenge value");
            return Ok(empty_response(StatusCode::BAD_REQUEST));
        }
    };

    set_challenge(challenges, challenge_name, challenge_value).await;
    Ok(empty_response(StatusCode::CREATED))
}

async fn set_challenge(challenges: Arc<Challenges>, txt_name: String, txt_value: String) {
    let mut challenges = challenges.0.lock().await;
    if challenges.contains_key(&txt_name) {
        tracing::warn!(challenge_name = %txt_name, "overwriting existing challenge");
    }
    tracing::info!(challenge_name = %txt_name, challenge_value = %txt_value, "set challenge");
    challenges.insert(txt_name, txt_value);
}

async fn handle_unset_challenge(
    req: Request<Incoming>,
    challenges: Arc<Challenges>,
) -> HyperResponseResult {
    let challenge_name = &req.uri().path()[REGISTER_PATH.len()..];
    unset_challenge(challenges, challenge_name).await;
    Ok(empty_response(StatusCode::NO_CONTENT))
}

async fn unset_challenge(challenges: Arc<Challenges>, txt_name: &str) {
    let mut challenges = challenges.0.lock().await;
    tracing::info!(challenge_name = %txt_name, "cleaned up challenge");
    challenges.remove(txt_name);
}

fn empty_response(status_code: StatusCode) -> Response<BoxBody<Bytes, hyper::Error>> {
    let mut resp = Response::new(empty_body());
    *resp.status_mut() = status_code;
    resp
}

fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full_response<T: Into<Bytes>>(
    status_code: StatusCode,
    chunk: T,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let mut resp = Response::new(full_body(chunk));
    *resp.status_mut() = status_code;
    resp
}

fn full_body<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}
