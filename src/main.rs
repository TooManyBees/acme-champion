use std::collections::HashMap;
use std::net::SocketAddr;
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
use tokio::{
    net::{TcpListener, TcpStream},
    signal::ctrl_c,
    sync::Mutex,
};

type Challenges = Arc<Mutex<HashMap<String, String>>>;

#[derive(Clone, Debug)]
struct Champion {
    challenges: Challenges,
}

impl Service<Request<Incoming>> for Champion {
    type Response = Response<BoxBody<Bytes, hyper::Error>>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let resp = match (req.method(), req.uri().path()) {
            (&Method::POST, "/register") => {
                Ok(empty_response(StatusCode::CREATED))
            },
            (&Method::DELETE, "/register") => {
                Ok(empty_response(StatusCode::NO_CONTENT))
            }
            _ => {
                Ok(empty_response(StatusCode::NOT_FOUND))
            }
        };

        Box::pin(async { resp })
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
                // TODO: unpack listen_http above so we can drop http_listener
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
fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}
