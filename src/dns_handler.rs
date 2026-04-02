use crate::dns::{ReadMessageResult, ValidQueryType, response_for_message};

use super::Challenges;

use std::net::{IpAddr, SocketAddr, UdpSocket};

pub fn bind_udp_socket(addr: Option<SocketAddr>) -> std::io::Result<Option<UdpSocket>> {
    addr.map(|addr| {
        let socket =
            UdpSocket::bind(addr).and_then(|socket| socket.set_nonblocking(true).map(|_| socket));
        tracing::debug!(%addr, "Listening for UDP traffic");
        socket
    })
    .transpose()
}

pub fn handle_dns(
    message: &[u8],
    socket: &UdpSocket,
    src_addr: SocketAddr,
    challenges: &Challenges,
) {
    tracing::debug!(remote_addr = %src_addr, "new UDP message");
    if !valid_return_address(&src_addr) {
        tracing::warn!(addr = %src_addr, "ignoring DNS request with invalid return address");
        return;
    }

    if let Some(response) = handle_request(message, challenges) {
        match socket.send_to(&response, src_addr) {
            Err(e) => {
                tracing::error!(error = %e, "error handling DNS request");
            }
            _ => {}
        }
    }
}

fn handle_request(message: &[u8], challenges: &Challenges) -> Option<Vec<u8>> {
    let (mut response, query_name, query_type, challenge_key) = match response_for_message(message)
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
            for value in challenges.named(&challenge_key) {
                tracing::debug!(
                    challenge_name = %challenge_key,
                    challenge_value = %value,
                    "found registered DNS challenge",
                );
                response.add_txt_answer(query_name.clone(), value);
            }
            if response.answers.is_empty() {
                tracing::debug!(challenge_name = %challenge_key, "DNS challenge not found");
            }
        }
        ValidQueryType::SOA => {
            if challenges.any(&challenge_key) {
                response.add_soa_answer(query_name.clone());
            }
        }
        ValidQueryType::NS => {
            if challenges.any(&challenge_key) {
                response.add_ns_answer(query_name.clone());
            }
        }
    }

    if response.answers.is_empty() {
        response.set_rcode_nxdomain();
    } else {
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
