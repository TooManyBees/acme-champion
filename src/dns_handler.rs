use crate::dns::{ReadMessageResult, Responder, UdpStream, ValidQueryType, response_for_message};

use super::Challenges;

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::net::UdpSocket;
use tracing::Instrument;

pub async fn bind_udp_stream(addr: SocketAddr) -> std::io::Result<UdpStream> {
    let dns_socket_4 = UdpSocket::bind(addr).await.map_err(|e| {
        tracing::error!(%addr, error = %e, "Failed to bind UDP listener");
        e
    })?;
    Ok(UdpStream::new(Arc::new(dns_socket_4)))
}

pub fn handle_dns(message: Vec<u8>, responder: Responder, challenges: &Arc<Challenges>) {
    let src_addr = responder.addr();
    tracing::debug!(remote_addr = %src_addr, "new UDP message");
    if !valid_return_address(&src_addr) {
        tracing::warn!(addr = %src_addr, "ignoring DNS request with invalid return address");
        return;
    }

    let challenges = challenges.clone();
    tokio::task::spawn(
        async move {
            if let Some(response) = handle_request(message, challenges).await {
                match responder.send(response).await {
                    Err(e) => {
                        tracing::error!(error = %e, "error handling DNS request");
                    }
                    _ => {}
                }
            }
        }
        .instrument(tracing::info_span!("process DNS query", remote_addr = %src_addr)),
    );
}

async fn handle_request(message: Vec<u8>, challenges: Arc<Challenges>) -> Option<Vec<u8>> {
    let (mut response, query_name, query_type, challenge_key) = match response_for_message(&message)
    {
        ReadMessageResult::Process {
            response,
            query_name,
            query_type,
            challenge_key,
        } => (response, query_name, query_type, challenge_key),
        ReadMessageResult::EarlyExit(response) => {
            return Some(response.to_bytes());
        }
        ReadMessageResult::DontRespond => return None,
    };

    match query_type {
        ValidQueryType::TXT => {
            for value in challenges.named(&challenge_key).await {
                response.add_txt_answer(query_name.clone(), value);
            }
        }
        ValidQueryType::SOA => {
            if challenges.any(&challenge_key).await {
                response.add_soa_answer(query_name.clone());
            }
        }
        ValidQueryType::NS => {
            if challenges.any(&challenge_key).await {
                response.add_ns_answer(query_name.clone());
            }
        }
    }

    if response.answers.is_empty() {
        tracing::debug!(challenge_name = %challenge_key, "DNS challenge not found");
        response.set_rcode_nxdomain();
    } else {
        tracing::debug!(challenge_name = %challenge_key, "found registered DNS challenge");
        response.set_rcode_noerror();
    }

    tracing::trace!(?response);
    tracing::info!(
        id = %response.transaction_id,
        challenge_name = %challenge_key,
        rcode = ?response.rcode,
        type = ?query_type,
        "answered DNS query",
    );

    Some(response.to_bytes())
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
