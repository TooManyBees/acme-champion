use crate::dns::{Message, Responder};
use crate::dns::{ReadMessageResult, response_for_message};

use super::Challenges;

use std::{
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::sync::mpsc::error::SendError;
use tracing::Instrument;

#[derive(Copy, Clone, Debug)]
pub enum DnsStreamResult {
    Processing,
    InvalidReturnAddress,
    ConnectionBroken,
    ConnectionError,
}

pub fn handle_dns(
    next_message: std::io::Result<(Vec<u8>, Responder)>,
    challenges: &Arc<Challenges>,
) -> DnsStreamResult {
    let (message, handler) = match next_message {
        Ok(message) => message,
        Err(e) => match e.kind() {
            ErrorKind::NotConnected | ErrorKind::ConnectionAborted => {
                tracing::error!(error = %e, "UDP connection broken");
                return DnsStreamResult::ConnectionBroken;
            }
            _ => {
                tracing::error!(error = %e, "UDP connection error");
                return DnsStreamResult::ConnectionError;
            }
        },
    };

    let src_addr = handler.addr();
    tracing::debug!(remote_addr = %src_addr, "new UDP message");
    if !valid_return_address(&src_addr) {
        tracing::warn!(addr = %src_addr, "ignoring DNS request with invalid return address");
        return DnsStreamResult::InvalidReturnAddress;
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

    return DnsStreamResult::Processing;
}

async fn handle_request(
    message: Vec<u8>,
    challenges: Arc<Challenges>,
    responder: Responder,
) -> Result<(), SendError<Message>> {
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
