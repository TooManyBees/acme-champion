use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::Full;
use hyper::{
    Request,
    Response,
    body::Bytes,
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use tokio::{
    net::{TcpListener, TcpStream},
    signal::ctrl_c,
    sync::Mutex,
};

type Challenges = Arc<Mutex<HashMap<String, String>>>;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let http_addr = SocketAddr::from(([127, 0, 0, 1], 8053));
    let http_listener = TcpListener::bind(http_addr).await?;

    let challenges: Challenges = Arc::new(Mutex::new(HashMap::new()));

    loop {
        tokio::select! {
            Ok((stream, _)) = http_listener.accept() => {
                handle_http(stream, challenges.clone());
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

fn handle_http(stream: TcpStream, _challenges: Challenges) {
    let io = TokioIo::new(stream);
    tokio::task::spawn(async move {
        if let Err(err) = http1::Builder::new()
            .serve_connection(io, service_fn(responder))
            .await
        {
            eprintln!("Error serving connection: {:?}", err);
        }
    });
}

async fn responder(_: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::new(Full::new(Bytes::from("response"))))
}
