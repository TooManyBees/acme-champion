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

async fn handle_request(
    message: SerialMessage,
    challenges: Arc<Challenges>,
    response_handler: BufDnsStreamHandle,
) -> Result<(), HandleMessageError> {
    let (mut response, query, name) = match read_message(&message) {
        Ok(result) => result,
        Err(HandleMessageError::ErrorResponse(response)) => {
            send_response(response, message.addr(), response_handler)?;
            return Ok(());
        }
        Err(HandleMessageError::Malformed(e)) => {
            tracing::debug!(error = %e, "error parsing message");
            // TODO: send a formerr response
            return Err(HandleMessageError::DontRespond);
        }
        Err(HandleMessageError::DontRespond) => return Err(HandleMessageError::DontRespond),
    };

    let challenges = challenges.0.lock().await;

    match challenges.get(&name) {
        Some(answer) => {
            tracing::debug!(challenge_name = %name, "found registered DNS challenge");
            response.set_response_code(ResponseCode::NoError);
            response.add_answer(challenge_rr(&query, answer));
        }
        None => {
            tracing::debug!(challenge_name = %name, "DNS challenge not found");
            response.set_response_code(ResponseCode::NXDomain);
        }
    };

    send_response(response, message.addr(), response_handler)?;
    Ok(())
}

fn send_response(
    response: Message,
    addr: SocketAddr,
    mut handler: BufDnsStreamHandle,
) -> Result<(), ProtoError> {
    let mut buffer = Vec::with_capacity(4096);
    let mut encoder = BinEncoder::new(&mut buffer);
    encoder.set_max_size(4096);
    response.emit(&mut encoder)?;
    handler.send(SerialMessage::new(buffer, addr))?;
    log_response(&response);
    Ok(())
}

fn log_response(response: &Message) {
    if let Some(query) = response.query() {
        let name_str = query.name.to_ascii();
        tracing::info!(
            name = tracing::field::display(name_str),
            rcode = ?response.response_code(),
            "answered DNS query",
        );
    } else {
        tracing::info!(
            rcode = ?response.response_code(),
            "answered DNS query",
        );
    }
}

fn read_message(
    message: &SerialMessage,
) -> Result<(Message, LowerQuery, String), HandleMessageError> {
    let mut decoder = BinDecoder::new(message.bytes());

    let mut response = Message::new();

    let header = Header::read(&mut decoder).map_err(|e| {
        tracing::warn!(error = %e, "malformed DNS header");
        e
    })?;

    tracing::debug!(header = ?header, "parsed DNS header");

    let response_header = Header::response_from_request(&header);
    response.set_header(response_header);

    if header.message_type() == HickoryMessageType::Response {
        tracing::debug!("ignoring DNS response");
        return Err(HandleMessageError::DontRespond);
    }

    if header.query_count() != 1 {
        response.set_response_code(ResponseCode::FormErr);
        return Err(HandleMessageError::ErrorResponse(response));
    }

    let query = match LowerQuery::read(&mut decoder) {
        Ok(q) => q,
        Err(e) => {
            tracing::warn!(error = %e, "malformed DNS query");
            response.set_response_code(ResponseCode::FormErr);
            return Err(HandleMessageError::ErrorResponse(response));
        }
    };

    response.add_query(query.original().clone());

    if !matches!(query.query_type(), RecordType::TXT) {
        tracing::debug!(query_type = %query.query_type(), "ignoring non-TXT DNS query");
        response.set_response_code(ResponseCode::Refused);
        return Err(HandleMessageError::ErrorResponse(response));
    }

    let name = query.name().to_utf8();
    const ACME_CHALLENGE_PREFIX: &'static str = "_acme-challenge.";
    if !name.starts_with(ACME_CHALLENGE_PREFIX) || name == ACME_CHALLENGE_PREFIX {
        tracing::debug!(query_name = %name, "ignoring non-acme DNS query");
        response.set_response_code(ResponseCode::Refused);
        return Err(HandleMessageError::ErrorResponse(response));
    }

    let domain_name = query.name().base_name().to_utf8();
    let domain_name = match domain_name.strip_suffix('.') {
        Some(name) => name.to_string(),
        None => domain_name,
    };

    tracing::debug!(query = ?query, "parsed DNS query");
    Ok((response, query, domain_name))
}

fn challenge_rr(query: &LowerQuery, answer: &String) -> Record {
    let name = query.original().name().clone();
    let rdata = RData::TXT(TXT::new(vec![answer.clone()]));
    Record::from_rdata(name, 30, rdata)
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
