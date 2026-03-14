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
    tokio::task::spawn(async move {
        match handle_request(message, challenges, dns_handle).await {
            Err(HandleMessageError::ProtoError(e)) => {
                tracing::error!(error = %e, "error handling DNS request")
            }
            _ => {}
        }
    }.instrument(tracing::info_span!("process DNS query", remote_addr = %src_addr)));

    return DnsStreamResult::Processing;
}

const ACME_CHALLENGE_PREFIX: &'static str = "_acme-challenge.";

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
        if !name.starts_with(ACME_CHALLENGE_PREFIX) || name == ACME_CHALLENGE_PREFIX {
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

#[derive(Copy, Clone, Debug)]
struct QueryHeader {
    transaction_id: u16,
    num_questions: u16,
}

#[derive(Copy, Clone, Debug)]
enum QueryHeaderError {
    TooShort,
    IsReply,
    NotStandardQuery,
}

impl QueryHeader {
    const LENGTH: usize = 12;

    fn from_bytes(bytes: &[u8]) -> Result<QueryHeader, QueryHeaderError> {
        if bytes.len() < 12 {
            return Err(QueryHeaderError::TooShort);
        }
        let transaction_id = u16_at(bytes, 0);

        if bytes[2] & 0b10000000 != 0 {
            return Err(QueryHeaderError::IsReply);
        }

        if bytes[2] & 0b01111000 != 0 {
            return Err(QueryHeaderError::NotStandardQuery);
        }

        let num_questions = u16_at(bytes, 4);

        Ok(QueryHeader {
            transaction_id,
            num_questions,
        })
    }
}

const TXT_TYPE: u16 = 16;
const IN_CLASS: u16 = 1;
const ACME_CHALLENGE_LABEL: &[u8] = b"_acme-challenge";

#[derive(Clone, Debug)]
struct TXTQuery {
    query_name_bytes: Vec<u8>,
    domain_name: String,
}

#[derive(Copy, Clone, Debug)]
enum TXTQueryError {
    TooShort,
    TooLong,
    InvalidLabelLength,
    InvalidNameEncoding,
    NotIN,
    NotTXT,
    NotACME,
}

impl TXTQuery {
    #[tracing::instrument(skip_all)]
    fn from_bytes(
        bytes: &[u8],
        mut cursor: usize,
    ) -> Result<(TXTQuery, usize), (TXTQueryError, usize)> {
        let mut labels = vec![];
        while cursor < bytes.len() {
            let (label, new_cursor) = read_label(bytes, cursor).map_err(|e| (e, 0))?;
            labels.push(label);
            cursor = new_cursor;
            if label.len() == 0 {
                break;
            }
        }
        tracing::trace!(num_labels = %labels.len(), "parsed query labels");

        let cursor_at_end = cursor + 4;

        if labels.len() == 0 || labels[0] != ACME_CHALLENGE_LABEL {
            return Err((TXTQueryError::NotACME, cursor_at_end));
        }

        let qtype = u16_at(bytes, cursor);
        tracing::trace!(%cursor, %qtype, "parsed query type");
        cursor += 2;
        if qtype != TXT_TYPE {
            return Err((TXTQueryError::NotTXT, cursor_at_end));
        }

        let qclass = u16_at(bytes, cursor);
        tracing::trace!(%cursor, %qclass, "parsed query class");
        // cursor += 2;
        if qclass != IN_CLASS {
            return Err((TXTQueryError::NotIN, cursor_at_end));
        }

        let mut query_name_bytes = Vec::with_capacity(255);
        let mut domain_name = String::with_capacity(255);
        for (i, label) in labels.into_iter().enumerate() {
            if !label.is_ascii() {
                return Err((TXTQueryError::InvalidNameEncoding, cursor_at_end));
            }

            if i > 0 {
                let string_label = String::from_utf8(label.to_vec())
                    .map_err(|_| (TXTQueryError::InvalidNameEncoding, cursor_at_end))?;
                if i > 1 {
                    domain_name.push('.');
                }
                domain_name.extend(string_label.chars());
            }

            if query_name_bytes.len() + label.len() + 1 > 255 {
                return Err((TXTQueryError::TooLong, cursor_at_end));
            }
            query_name_bytes.push(label.len() as u8);
            query_name_bytes.extend(label);
        }

        Ok((
            TXTQuery {
                query_name_bytes,
                domain_name,
            },
            cursor_at_end,
        ))
    }
}

fn write_dns_header(buffer: &mut Vec<u8>) {}

fn write_dns_answer(buffer: &mut Vec<u8>, answer_name: &str, answer_value: &str) {}

fn u16_at(bytes: &[u8], pos: usize) -> u16 {
    (bytes[pos] as u16).unbounded_shl(8) + bytes[pos + 1] as u16
}

#[tracing::instrument(skip(bytes))]
fn read_label(bytes: &[u8], cursor: usize) -> Result<(&[u8], usize), TXTQueryError> {
    match bytes.get(cursor) {
        Some(len) if len & 0b11000000 == 0 => {
            tracing::trace!("found label at cursor");
            let (label, new_cursor) = label_at(bytes, cursor)?;
            return Ok((label, new_cursor));
        }
        Some(off) if off & 0b11000000 == 0b11000000 => {
            let ptr = (off & 0b00111111) as usize;
            tracing::trace!(ptr_offset = %ptr, "found label at pointer");
            if ptr >= cursor {
                return Err(TXTQueryError::InvalidLabelLength);
            }
            let (label, _) = label_at(bytes, ptr)?;
            Ok((label, cursor))
        }
        Some(_) => return Err(TXTQueryError::InvalidLabelLength),
        None => return Err(TXTQueryError::TooShort),
    }
}

#[tracing::instrument(skip(bytes))]
fn label_at(bytes: &[u8], mut cursor: usize) -> Result<(&[u8], usize), TXTQueryError> {
    if bytes.len() <= cursor {
        return Err(TXTQueryError::TooShort);
    }

    let label_len = bytes[cursor] as usize;
    tracing::trace!(%cursor, length = %label_len, "parsed label length");
    cursor += 1;

    if cursor + label_len > bytes.len() {
        return Err(TXTQueryError::TooShort);
    }

    let result = &bytes[cursor..(cursor + label_len)];
    cursor += label_len;
    tracing::trace!(new_cursor = %cursor, length = %label_len, "parsed label");

    Ok((result, cursor))
}
