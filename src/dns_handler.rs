use crate::dns::{ReadMessageResult, response_for_message};

use super::Challenges;

use hickory_proto::{
    ProtoError,
    op::{Header, LowerQuery, Message, ResponseCode, header::MessageType as HickoryMessageType},
    rr::{rdata::txt::TXT, record_data::RData, record_type::RecordType, resource::Record},
    runtime::TokioRuntimeProvider,
    serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder},
    udp::UdpStream,
    xfer::{BufDnsStreamHandle, DnsStreamHandle, SerialMessage},
};
use std::{
    io::{Error as IoError, ErrorKind},
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::net::UdpSocket;
use tracing::Instrument;

pub fn make_dns_stream(
    udp_socket: UdpSocket,
) -> (UdpStream<TokioRuntimeProvider>, BufDnsStreamHandle) {
    UdpStream::<TokioRuntimeProvider>::with_bound(
        udp_socket,
        SocketAddr::from(([255, 255, 255, 254], 0)),
    )
}

#[derive(Copy, Clone, Debug)]
pub enum DnsStreamResult {
    Processing,
    InvalidReturnAddress,
    ConnectionBroken,
    ConnectionError,
}

pub fn handle_dns(
    next_message: Option<Result<SerialMessage, IoError>>,
    dns_handle: BufDnsStreamHandle,
    challenges: &Arc<Challenges>,
) -> DnsStreamResult {
    let message = match next_message {
        Some(Ok(message)) => message,
        Some(Err(e)) => match e.kind() {
            ErrorKind::NotConnected | ErrorKind::ConnectionAborted => {
                tracing::error!(error = %e, "UDP connection broken");
                return DnsStreamResult::ConnectionBroken;
            }
            _ => {
                tracing::error!(error = %e, "UDP connection error");
                return DnsStreamResult::ConnectionError;
            }
        },
        None => {
            tracing::error!("UDP connection closed");
            return DnsStreamResult::ConnectionBroken;
        }
    };

    let src_addr = message.addr();
    tracing::debug!(remote_addr = %src_addr, "new UDP message");
    if !valid_return_address(&src_addr) {
        tracing::warn!(addr = %src_addr, "ignoring DNS request with invalid return address");
        return DnsStreamResult::InvalidReturnAddress;
    }

    let dns_handle = dns_handle.with_remote_addr(src_addr);
    let challenges = challenges.clone();
    tokio::task::spawn(
        async move {
            // match handle_request(message, challenges, dns_handle).await {
            //     Err(HandleMessageError::Malformed(e)) => {
            //         tracing::error!(error = %e, "error handling DNS request")
            //     }
            //     _ => {}
            // }
            match handle_request_2(message, challenges, dns_handle).await {
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

#[derive(Clone, Debug)]
enum HandleMessageError {
    DontRespond,
    ErrorResponse(Message),
    Malformed(ProtoError),
}

impl From<ProtoError> for HandleMessageError {
    fn from(e: ProtoError) -> Self {
        HandleMessageError::Malformed(e)
    }
}

async fn handle_request_2(
    message: SerialMessage,
    challenges: Arc<Challenges>,
    mut response_handler: BufDnsStreamHandle,
) -> Result<(), ProtoError> {
    let (mut response, query_name, challenge_key) = match response_for_message(message.bytes()) {
        ReadMessageResult::Process {
            response,
            query_name,
            challenge_key,
        } => (response, query_name, challenge_key),
        ReadMessageResult::EarlyExit(response) => {
            let response_bytes = response.to_bytes();
            response_handler.send(SerialMessage::new(response_bytes, message.addr()))?;
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

    response_handler.send(SerialMessage::new(response_bytes, message.addr()))?;

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
