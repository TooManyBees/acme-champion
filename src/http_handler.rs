use super::{Challenge, Challenges};

use std::convert::Infallible;
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

type HyperBodyResponse = Response<BoxBody<Bytes, Infallible>>;
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
    type Response = HyperBodyResponse;
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
                (_, path) if path.starts_with(REGISTER_PATH) => {
                    Ok(empty_response(StatusCode::METHOD_NOT_ALLOWED))
                }
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
    let mut result = String::new();
    for challenge in challenges.all().await.iter() {
        result.push_str(&challenge.domain);
        result.push(' ');
        result.push_str(&challenge.name);
        result.push(' ');
        result.push_str(&format!("{:?}", challenge.value));
        result.push('\n');
    }
    Ok(full_response(StatusCode::OK, result))
}

async fn handle_set_challenge(
    req: Request<Incoming>,
    challenges: Arc<Challenges>,
) -> HyperResponseResult {
    let challenge = match challenge_from_req(&req) {
        Ok(c) => c,
        Err(_) => return Ok(empty_response(StatusCode::BAD_REQUEST)),
    };

    challenges.set(challenge.clone()).await;
    tracing::info!(domain_name = %challenge.domain, challenge_name = %challenge.name, challenge_value = %challenge.value, "set challenge");
    Ok(empty_response(StatusCode::CREATED))
}

async fn handle_unset_challenge(
    req: Request<Incoming>,
    challenges: Arc<Challenges>,
) -> HyperResponseResult {
    let challenge = match challenge_from_req(&req) {
        Ok(c) => c,
        Err(_) => return Ok(empty_response(StatusCode::BAD_REQUEST)),
    };

    challenges.cleanup(&challenge).await;
    Ok(empty_response(StatusCode::NO_CONTENT))
}

fn challenge_from_req(req: &Request<Incoming>) -> Result<Challenge, ()> {
    let domain = req.uri().path()[REGISTER_PATH.len()..]
        .trim_end_matches('.')
        .to_string();
    let name_header = match req.headers().get("X-ACME-Challenge-Name") {
        Some(value) => value,
        None => {
            tracing::warn!(domain_name = %domain, "ignoring HTTP request without X-ACME-Challenge-Name header");
            return Err(());
        }
    };
    let name = match name_header.to_str() {
        Ok(s) => s.trim_end_matches('.').to_string(),
        Err(_) => {
            tracing::warn!(domain_name = %domain, "ignoring HTTP request without non-visible ASCII challenge name");
            return Err(());
        }
    };
    let value_header = match req.headers().get("X-ACME-Challenge-Value") {
        Some(value) => value,
        None => {
            tracing::warn!(domain_name = %domain, challenge_name = %name, "ignoring HTTP request without X-ACME-Challenge-Value header");
            return Err(());
        }
    };
    let value = match value_header.to_str() {
        Ok(s) => s.to_string(),
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

fn empty_response(status_code: StatusCode) -> HyperBodyResponse {
    let mut resp = Response::new(Empty::new().boxed());
    *resp.status_mut() = status_code;
    resp
}

fn full_response<T: Into<Bytes>>(status_code: StatusCode, chunk: T) -> HyperBodyResponse {
    let mut resp = Response::new(Full::new(chunk.into()).boxed());
    *resp.status_mut() = status_code;
    resp
}
