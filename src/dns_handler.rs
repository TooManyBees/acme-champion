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
    net::SocketAddr,
    sync::Arc,
};
use tokio::net::UdpSocket;

pub fn make_dns_stream(
    udp_socket: UdpSocket,
) -> (UdpStream<TokioRuntimeProvider>, BufDnsStreamHandle) {
    UdpStream::<TokioRuntimeProvider>::with_bound(
        udp_socket,
        SocketAddr::from(([255, 255, 255, 255], 0)),
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
    // TODO validate src_addr

    let dns_handle = dns_handle.with_remote_addr(src_addr);
    let challenges = challenges.clone();
    tokio::task::spawn(async move {
        handle_request(message, challenges, dns_handle).await;
    });
}

const ACME_CHALLENGE_LABEL: &'static str = "_acme-challenge.";

async fn handle_request(
    message: SerialMessage,
    challenges: Arc<Challenges>,
    mut response_handler: BufDnsStreamHandle,
) -> Result<(), ProtoError> {
    let (header, queries) = read_message(&message)?;

    let challenges = challenges.0.lock().await;
    for (query, name) in queries.into_iter().take(1) {
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
    }

    Ok(())
}

fn read_message(
    message: &SerialMessage,
) -> Result<(Header, Vec<(LowerQuery, String)>), ProtoError> {
    let mut decoder = BinDecoder::new(message.bytes());

    let header = Header::read(&mut decoder).map_err(|e| {
        tracing::warn!(error = %e, "malformed DNS header");
        e
    })?;

    tracing::debug!(header = ?header, "parsed DNS header");

    if header.message_type() == MessageType::Response {
        // FIXME: create an error enum to represent skipping responses
        tracing::debug!("ignoring DNS response");
        return Ok((header, vec![]));
    }

    let query_count = header.query_count() as usize;
    let mut queries = Vec::with_capacity(query_count);
    for _ in 0..query_count {
        let query = LowerQuery::read(&mut decoder).map_err(|e| {
            // TODO: consider continuing on error, rather than early exiting
            tracing::warn!(error = %e, "malformed DNS query");
            e
        })?;
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
        queries.push((query, domain_name));
    }

    tracing::debug!(queries = ?queries, "parsed DNS queries");

    Ok((header, queries))
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
