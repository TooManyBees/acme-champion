use crate::dns::{ReadMessageResult, Responder, UdpStream, response_for_message};

use super::Challenges;

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::error::SendError;
use tracing::Instrument;

pub async fn bind_udp_stream(addr: IpAddr, port: u16) -> std::io::Result<UdpStream> {
    let dns_addr = SocketAddr::new(addr, port);
    let dns_socket_4 = UdpSocket::bind(dns_addr).await.map_err(|e| {
        tracing::error!(addr = %dns_addr, error = %e, "Failed to bind UDP listener");
        e
    })?;
    tracing::debug!(addr = %dns_addr, "Listening for UDP traffic");
    Ok(UdpStream::new(dns_socket_4))
}

pub fn handle_dns(message: Vec<u8>, handler: Responder, challenges: &Arc<Challenges>) {
    let src_addr = handler.addr();
    tracing::debug!(remote_addr = %src_addr, "new UDP message");
    if !valid_return_address(&src_addr) {
        tracing::warn!(addr = %src_addr, "ignoring DNS request with invalid return address");
        return;
    }

    let challenges = challenges.clone();
    tokio::task::spawn(
        async move {
            match handle_request(message, challenges, handler).await {
                Err(e) => {
                    tracing::error!(error = %e, "error handling DNS request");
                }
                _ => {}
            }
        }
        .instrument(tracing::info_span!("process DNS query", remote_addr = %src_addr)),
    );
}

async fn handle_request(
    message: Vec<u8>,
    challenges: Arc<Challenges>,
    responder: Responder,
) -> Result<(), SendError<()>> {
    let (mut response, query_name, challenge_key) = match response_for_message(&message) {
        ReadMessageResult::Process {
            response,
            query_name,
            challenge_key,
        } => (response, query_name, challenge_key),
        ReadMessageResult::EarlyExit(response) => {
            let response_bytes = response.to_bytes();
            responder.send(response_bytes).await?;
            return Ok(());
        }
        ReadMessageResult::DontRespond => return Ok(()),
    };

    let challenges = challenges.0.lock().await;

    match challenges.get(&challenge_key) {
        Some(value) => {
            tracing::debug!(challenge_name = %challenge_key, "found registered DNS challenge");
            response.set_rcode_noerror();
            response.set_answer(query_name, &value);
        }
        None => {
            tracing::debug!(challenge_name = %challenge_key, "DNS challenge not found");
            response.set_rcode_nxdomain();
        }
    }

    tracing::debug!(?response);
    tracing::info!(challenge_name = %challenge_key, rcode = ?response.rcode, "answered DNS query");

    let response_bytes = response.to_bytes();

    responder.send(response_bytes).await?;

    Ok(())
}

fn valid_return_address(src_addr: &SocketAddr) -> bool {
    if src_addr.port() == 0 {
        return false;
    }
    match src_addr.ip() {
        IpAddr::V4(addr) => {
            if addr.is_unspecified() || addr.is_broadcast() {
                return false;
            }
        }
        IpAddr::V6(addr) => {
            if addr.is_unspecified() {
                return false;
            }
        }
    }
    return true;
}
