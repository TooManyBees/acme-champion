use crate::challenges::Challenges;
use crate::config::ServerIps;
use crate::dns::{ReadMessageResult, ValidQueryType, response_for_message};
use mio::net::UdpSocket;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};

pub fn bind_udp_socket(
    addr: Option<SocketAddr>,
    required: bool,
) -> std::io::Result<Option<UdpSocket>> {
    if let Some(addr) = addr {
        match UdpSocket::bind(addr) {
            Ok(socket) => {
                tracing::info!(%addr, "Listening for UDP traffic");
                return Ok(Some(socket));
            }
            Err(error) if required => {
                tracing::error!(%addr, %error, "Failed to bind UDP socket");
                Err(error)
            }
            Err(error) => {
                tracing::warn!(%addr, %error, "Failed to bind UDP socket");
                Ok(None)
            }
        }
    } else {
        Ok(None)
    }
}

pub fn handle_dns(
    message: &[u8],
    socket: &UdpSocket,
    server_ips: ServerIps,
    src_addr: SocketAddr,
    challenges: &Challenges,
) {
    tracing::debug!(remote_addr = %src_addr, "new UDP message");
    if !valid_return_address(&src_addr) {
        tracing::debug!(addr = %src_addr, "ignoring UDP message with invalid return address");
        return;
    }

    if let Some(response) = handle_request(message, server_ips, challenges) {
        let mut warn_on_block = true;
        loop {
            match socket.send_to(&response, src_addr) {
                Ok(_) => break,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    if warn_on_block {
                        warn_on_block = false;
                        tracing::warn!(%error, addr = %src_addr, "UDP socket unexpectedly blocked on response");
                    }
                }
                Err(error) => {
                    tracing::error!(%error, addr = %src_addr, "error responding to DNS request");
                    break;
                }
            }
        }
    }
}

fn handle_request(
    message: &[u8],
    server_ips: ServerIps,
    challenges: &Challenges,
) -> Option<Vec<u8>> {
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
                response.add_txt_answer(query_name.clone(), value.to_string());
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
        ValidQueryType::A => {
            if let Some(ip) = server_ips.v4 {
                response.add_a_answer(query_name.clone(), ip);
            }
        }
        ValidQueryType::AAAA => {
            if let Some(ip) = server_ips.v6 {
                response.add_aaaa_answer(query_name.clone(), ip);
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
