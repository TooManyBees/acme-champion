use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Body, Bytes, Incoming},
    server::conn::http1,
    service::Service,
};
use hyper_util::rt::TokioIo;
use tokio::{
    net::{TcpListener, TcpStream},
    signal::ctrl_c,
    sync::Mutex,
};

type Challenges = Arc<Mutex<HashMap<String, String>>>;

type HyperBodyResponse = Response<BoxBody<Bytes, hyper::Error>>;
type HyperResponseResult = Result<HyperBodyResponse, hyper::Error>;

const REGISTER_PATH: &'static str = "/register/";

#[derive(Clone, Debug)]
struct Champion {
    challenges: Challenges,
}

impl Service<Request<Incoming>> for Champion {
    type Response = Response<BoxBody<Bytes, hyper::Error>>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let challenges = self.challenges.clone();
        Box::pin(async {
            match (req.method(), req.uri().path()) {
                (&Method::GET, "/") => {
                    Self::handle_get_challenges(challenges).await
                }
                (&Method::POST, path) if path.starts_with(REGISTER_PATH) => {
                    Self::handle_set_challenge(req, challenges).await
                }
                (&Method::DELETE, path) if path.starts_with(REGISTER_PATH) => {
                    Self::handle_unset_challenge(req, challenges).await
                }
                _ => Ok(empty_response(StatusCode::NOT_FOUND)),
            }
        })
    }
}

impl Champion {
    async fn handle_get_challenges(challenges: Challenges) -> HyperResponseResult {
        let challenges = challenges.lock().await;
        let mut result = String::new();
        for (key, value) in challenges.iter() {
            result.push_str(key);
            result.push(' ');
            result.push_str(value);
            result.push('\n');
        }
        Ok(full_response(StatusCode::OK, result))
    }

    async fn handle_set_challenge(req: Request<Incoming>, challenges: Challenges) -> HyperResponseResult {
        let body_size = req.body().size_hint().upper().unwrap_or(u64::MAX);
        if body_size > 1024 {
            return Ok(empty_response(StatusCode::PAYLOAD_TOO_LARGE));
        }

        let challenge_name = req.uri().path()[REGISTER_PATH.len()..].to_string();
        let body = req.collect().await?.to_bytes();
        let challenge_value = match String::from_utf8(body.to_vec()) {
            Ok(v) => v,
            Err(_) => return Ok(empty_response(StatusCode::BAD_REQUEST)),
        };

        Self::set_challenge(challenges, String::from(""), challenge_name, challenge_value).await;
        Ok(empty_response(StatusCode::CREATED))
    }

    async fn set_challenge(challenges: Challenges, _name: String, txt_name: String, txt_value: String) {
        let mut challenges = challenges.lock().await;
        if challenges.contains_key(&txt_name) {
            eprintln!("Overwriting existing challenge for {txt_name}");
        }
        challenges.insert(txt_name, txt_value);
    }

    async fn handle_unset_challenge(req: Request<Incoming>, challenges: Challenges) -> HyperResponseResult {
        let challenge_name = &req.uri().path()[REGISTER_PATH.len()..];
        Self::unset_challenge(challenges, String::from(""), challenge_name).await;
        Ok(empty_response(StatusCode::NO_CONTENT))
    }

    async fn unset_challenge(challenges: Challenges, _name: String, txt_name: &str) {
        let mut challenges = challenges.lock().await;
        challenges.remove(txt_name);
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let http_addr = SocketAddr::from(([127, 0, 0, 1], 8053));
    let http_listener = TcpListener::bind(http_addr).await?;

    let challenges: Challenges = Arc::new(Mutex::new(HashMap::new()));

    let champion = Champion {
        challenges,
    };

    loop {
        tokio::select! {
            Ok((stream, _)) = http_listener.accept() => {
                let service = champion.clone();
                handle_http(stream, service);
            }
            _ = shutdown_signal() => {
                drop(http_listener);
                break;
            }
        }
    }

    eprintln!("bye!");
    Ok(())
}

async fn shutdown_signal() {
    ctrl_c().await.expect("failed to install signal handler");
}

fn handle_http(stream: TcpStream, service: Champion) {
    let io = TokioIo::new(stream);
    tokio::task::spawn(async move {
        if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
            eprintln!("Error serving connection: {:?}", err);
        }
    });
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
