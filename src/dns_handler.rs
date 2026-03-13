use super::Challenges;

use hickory_proto::{
    ProtoError,
    op::{Header, LowerQuery, Message, ResponseCode, header::MessageType},
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

pub fn make_dns_stream(
    udp_socket: UdpSocket,
) -> (UdpStream<TokioRuntimeProvider>, BufDnsStreamHandle) {
    UdpStream::<TokioRuntimeProvider>::with_bound(
        udp_socket,
        SocketAddr::from(([255, 255, 255, 254], 0)),
    )
}

pub fn handle_dns(
    next_message: Option<Result<SerialMessage, IoError>>,
    dns_handle: BufDnsStreamHandle,
    challenges: &Arc<Challenges>,
) {
    let message = match next_message {
        Some(Ok(message)) => message,
        Some(Err(e)) => match e.kind() {
            ErrorKind::NotConnected | ErrorKind::ConnectionAborted => {
                tracing::error!(error = %e, "UDP connection broken");
                return; // TODO: return an error which breaks out of select loop
            }
            _ => {
                tracing::error!(error = %e, "UDP connection error");
                return;
            }
        },
        None => {
            tracing::error!("UDP connection closed");
            return; // TODO: return an error which breaks out of select loop
        }
    };

    let src_addr = message.addr();
    tracing::debug!(remote_addr = %src_addr, "new UDP message");
    if src_addr.port() == 0 {
        return;
    }
    match src_addr.ip() {
        IpAddr::V4(addr) => {
            if addr.is_unspecified() || addr.is_broadcast() {
                return;
            }
        }
        IpAddr::V6(addr) => {
            if addr.is_unspecified() {
                return;
            }
        }
    }

    let dns_handle = dns_handle.with_remote_addr(src_addr);
    let challenges = challenges.clone();
    tokio::task::spawn(async move {
        match handle_request(message, challenges, dns_handle).await {
            Err(HandleMessageError::ProtoError(e)) => {
                tracing::error!(error = %e, "error handling DNS request")
            }
            _ => {}
        }
    });
}

const ACME_CHALLENGE_LABEL: &'static str = "_acme-challenge.";

#[derive(Clone, Debug)]
enum HandleMessageError {
    SkippingResponse,
    NoTxtQueries,
    ProtoError(ProtoError),
}

impl From<ProtoError> for HandleMessageError {
    fn from(e: ProtoError) -> Self {
        HandleMessageError::ProtoError(e)
    }
}

async fn handle_request(
    message: SerialMessage,
    challenges: Arc<Challenges>,
    mut response_handler: BufDnsStreamHandle,
) -> Result<(), HandleMessageError> {
    let (header, query, name) = read_message(&message)?;

    let challenges = challenges.0.lock().await;

    tracing::debug!(?challenges, ?name);
    let response = match challenges.get(&name) {
        Some(answer) => {
            tracing::debug!(challenge_name = %name, "found registered DNS challenge");
            challenge_response(&header, &query, Some(answer))
        }
        None => {
            tracing::debug!(challenge_name = %name, "DNS challenge not found");
            challenge_response(&header, &query, None)
        }
    };
    let mut buffer = Vec::with_capacity(4096);
    let mut encoder = BinEncoder::new(&mut buffer);
    encoder.set_max_size(4096);
    response.emit(&mut encoder)?;
    response_handler.send(SerialMessage::new(buffer, message.addr()))?;

    Ok(())
}

fn read_message(
    message: &SerialMessage,
) -> Result<(Header, LowerQuery, String), HandleMessageError> {
    let mut decoder = BinDecoder::new(message.bytes());

    let header = Header::read(&mut decoder).map_err(|e| {
        tracing::warn!(error = %e, "malformed DNS header");
        e
    })?;

    tracing::debug!(header = ?header, "parsed DNS header");

    if header.message_type() == MessageType::Response {
        tracing::debug!("ignoring DNS response");
        return Err(HandleMessageError::SkippingResponse);
    }

    let query_count = header.query_count() as usize;
    let mut found = None;
    for _ in 0..query_count {
        let query = match LowerQuery::read(&mut decoder) {
            Ok(q) => q,
            Err(e) => {
                tracing::warn!(error = %e, "malformed DNS query");
                continue;
            }
        };

        if !matches!(query.query_type(), RecordType::TXT) {
            tracing::debug!(query_type = %query.query_type(), "ignoring non-TXT DNS query");
            continue;
        }

        let name = query.name().to_utf8();
        if !name.starts_with(ACME_CHALLENGE_LABEL) || name == ACME_CHALLENGE_LABEL {
            tracing::debug!(query_name = %name, "ignoring non-acme DNS query");
            continue;
        }

        let domain_name = query.name().base_name().to_utf8();
        let domain_name = match domain_name.strip_suffix('.') {
            Some(name) => name.to_string(),
            None => domain_name,
        };

        found = Some((query, domain_name));
        break;
    }

    match found {
        Some((query, name)) => {
            tracing::debug!(query = ?query, "parsed DNS query");
            Ok((header, query, name))
        }
        None => {
            tracing::debug!("no queries found for TXT records");
            Err(HandleMessageError::NoTxtQueries)
        }
    }
}

fn challenge_response(
    request_header: &Header,
    query: &LowerQuery,
    answer: Option<&String>,
) -> Message {
    let mut response_header = Header::response_from_request(request_header);
    response_header.set_authoritative(true);

    let mut message = Message::new();

    message.add_query(query.original().clone());

    match answer {
        Some(answer_value) => {
            response_header.set_response_code(ResponseCode::NoError);
            let name = query.original().name().clone();
            let rdata = RData::TXT(TXT::new(vec![answer_value.clone()]));
            let record = Record::from_rdata(name, 30, rdata);
            message.add_answer(record);
        }
        None => {
            response_header.set_response_code(ResponseCode::NXDomain);
        }
    }

    message.set_header(response_header);

    message
}
