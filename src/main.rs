mod challenge_register;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use challenge_register::ChallengeRegister;

use hyper::server::conn::http1;
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
    eprintln!("Listening for TCP traffic on 8053");

    let challenges: Challenges = Arc::new(Mutex::new(HashMap::new()));

    let challenge_register = ChallengeRegister::new(challenges.clone());

    loop {
        tokio::select! {
            Ok((stream, _)) = http_listener.accept() => {
                let service = challenge_register.clone();
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

fn handle_http(stream: TcpStream, service: ChallengeRegister) {
    let io = TokioIo::new(stream);
    tokio::task::spawn(async move {
        if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
            eprintln!("Error serving connection: {:?}", err);
        }
    });
}
