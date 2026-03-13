use super::Challenges;

use hickory_proto::{
    ProtoError,
    op::{Header, LowerQuery, header::MessageType},
    rr::record_type::RecordType,
    runtime::TokioRuntimeProvider,
    serialize::binary::{BinDecodable, BinDecoder},
    udp::UdpStream,
    xfer::{BufDnsStreamHandle, SerialMessage},
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
        }
        None => {
            tracing::error!("UDP connection closed");
            return // TODO: return an error which breaks out of select loop
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
    response_handler: BufDnsStreamHandle,
) -> Result<(), ProtoError> {
    // let src_addr = message.addr();

    let queries = read_queries_from_message(&message)?;

    let challenges = challenges.0.lock().await;
    for q in queries {
        match challenges.get(&q) {
            Some(answer) => {
                tracing::debug!(challenge_name = %q, "found registered DNS challenge");

            }
            None => {
                tracing::debug!(challenge_name = %q, "DNS challenge not found");

            }
        }

    }

    Ok(())
}

fn read_queries_from_message(message: &SerialMessage) -> Result<Vec<String>, ProtoError> {
    let mut decoder = BinDecoder::new(message.bytes());

    let header = Header::read(&mut decoder).map_err(|e| {
        tracing::warn!(error = %e, "malformed DNS header");
        e
    })?;

    tracing::debug!(header = ?header, "parsed DNS header");

    if header.message_type() == MessageType::Response {
        // TODO: create an error enum to represent skipping responses
        tracing::debug!("ignoring DNS response");
        return Ok(vec![]);
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
        queries.push(name);
    }

    tracing::debug!(queries = ?queries, "parsed DNS queries");

    Ok(queries)
}
