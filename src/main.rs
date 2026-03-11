use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

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
    // sync::Mutex,
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
        let fake_domain = String::from("hithere.com");
        let fake_name = String::from("_acme_challenge.hithere.com");
        let fake_challenge = String::from("super-secret-string");
        let resp = match (req.method(), req.uri().path()) {
            (&Method::GET, "/") => {
                let result = self.get_challenges();
                Ok(full_response(StatusCode::OK, result))
            }
            (&Method::POST, "/register") => {
                self.set_challenge(fake_domain, fake_name, fake_challenge);
                Ok(empty_response(StatusCode::CREATED))
            }
            (&Method::DELETE, "/register") => {
                self.unset_challenge(fake_domain, fake_name);
                Ok(empty_response(StatusCode::NO_CONTENT))
            }
            _ => Ok(empty_response(StatusCode::NOT_FOUND)),
        };

        Box::pin(async { resp })
    }
}

impl Champion {
    fn get_challenges(&self) -> String {
        let challenges = self.challenges.lock().unwrap();
        let mut result = String::new();
        for (key, value) in challenges.iter() {
            result.push_str(key);
            result.push(' ');
            result.push_str(value);
            result.push('\n');
        }
        result
    }

    fn set_challenge(&self, _name: String, txt_name: String, txt_value: String) {
        let mut challenges = self.challenges.lock().unwrap();
        if challenges.contains_key(&txt_name) {
            eprintln!("Overwriting existing challenge for {txt_name}");
        }
        challenges.insert(txt_name, txt_value);
    }

    fn unset_challenge(&self, _name: String, txt_name: String) {
        let mut challenges = self.challenges.lock().unwrap();
        challenges.remove(&txt_name);
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
