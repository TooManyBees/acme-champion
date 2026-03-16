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

const ACME_CHALLENGE_PREFIX: &'static str = "_acme-challenge.";

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
            response.rcode = RCode::NoError;
            let answer = Answer {
                name: query_name,
                value: value.clone().into_bytes(),
            };
            response.answer = Some(answer);
        }
        None => {
            tracing::debug!(challenge_name = %challenge_key, "DNS challenge not found");
            response.rcode = RCode::NXDomain;
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

fn send_response(response: Message, addr: SocketAddr, mut handler: BufDnsStreamHandle) -> Result<(), ProtoError> {
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

#[derive(Clone, Debug)]
enum ReadMessageResult {
    Process {
        response: Response,
        query_name: Vec<u8>,
        challenge_key: String,
    },
    EarlyExit(Response),
    DontRespond,
}

fn response_for_message(bytes: &[u8]) -> ReadMessageResult {
    let mut response = Response::new();

    let header = match QueryHeader::from_bytes(bytes) {
        Ok(header) => header,
        Err(QueryHeaderError::TooShort) => {
            tracing::debug!("ignoring malformed message");
            return ReadMessageResult::DontRespond;
        }
    };
    tracing::debug!(?header, "parsed DNS header");

    if header.message_type == MessageType::Reply {
        tracing::debug!("ignoring DNS response");
        return ReadMessageResult::DontRespond;
    }

    if header.opcode != OpCode::Standard {
        tracing::debug!("ignoring non-standard query");
        response.rcode = RCode::Refused;
        return ReadMessageResult::EarlyExit(response);
    }

    response.transaction_id = header.transaction_id;

    if header.num_questions != 1 {
        response.rcode = RCode::FormErr;
        return ReadMessageResult::EarlyExit(response);
    }

    let (query, _cursor) = match Query::from_bytes(&bytes, QueryHeader::LENGTH) {
        Ok(q) => q,
        Err(e) => {
            response.rcode = RCode::FormErr;
            match e {
                (QueryError::TooShort, _) => {
                    tracing::debug!("query label length exceeds message size");
                }
                (QueryError::TooLong, _) => {
                    tracing::debug!("query name size exceeds maximum length of 255");
                }
                (QueryError::InvalidLabelLength(octet), _) => {
                    tracing::debug!(octet, "query label length octet is malformed");
                }
                (QueryError::InvalidNameEncoding, _) => {
                    tracing::debug!("query label is not valid ASCII");
                }
            }
            return ReadMessageResult::EarlyExit(response);
        }
    };

    tracing::debug!(?query, "parsed DNS query");

    response.query = Some(query.clone());

    // TODO: detect and return hardcoded response to NS query

    if query.query_type != TXT_TYPE {
        tracing::debug!(query_type = %query.query_type, "ignoring non-TXT DNS query");
        response.rcode = RCode::Refused;
        return ReadMessageResult::EarlyExit(response);
    }

    if !query.is_acme_challenge {
        tracing::debug!(query_name = %query.query_name_string, "ignoring non-acme DNS query");
        response.rcode = RCode::Refused;
        return ReadMessageResult::EarlyExit(response);
    }

    let challenge_key = query
        .query_name_string
        .trim_end_matches('.')
        .trim_start_matches(ACME_CHALLENGE_PREFIX)
        .to_string();

    ReadMessageResult::Process {
        response,
        query_name: query.query_name_bytes,
        challenge_key,
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

#[derive(Copy, Clone, Debug)]
struct QueryHeader {
    transaction_id: u16,
    message_type: MessageType,
    opcode: OpCode,
    num_questions: u16,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum MessageType {
    Query,
    Reply,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum OpCode {
    Standard,
    Inverse,
    Status,
    Other,
}

#[derive(Copy, Clone, Debug)]
enum QueryHeaderError {
    TooShort,
}

impl QueryHeader {
    const LENGTH: usize = 12;

    fn from_bytes(bytes: &[u8]) -> Result<QueryHeader, QueryHeaderError> {
        if bytes.len() < 12 {
            return Err(QueryHeaderError::TooShort);
        }
        let transaction_id = u16_at(bytes, 0);

        let message_type = if bytes[2] & 0b10000000 == 0 {
            MessageType::Query
        } else {
            MessageType::Reply
        };

        let opcode = match (bytes[2] >> 3) & 0b00001111 {
            0 => OpCode::Standard,
            1 => OpCode::Inverse,
            2 => OpCode::Status,
            _ => OpCode::Other,
        };

        let num_questions = u16_at(bytes, 4);

        let header = QueryHeader {
            transaction_id,
            message_type,
            opcode,
            num_questions,
        };

        Ok(header)
    }
}

const TXT_TYPE: u16 = 16;
const IN_CLASS: u16 = 1;
const ACME_CHALLENGE_LABEL: &[u8] = b"_acme-challenge";
const ANSWER_TTL: u32 = 30;

#[derive(Clone, Debug)]
struct Query {
    query_name_bytes: Vec<u8>,
    query_name_string: String,
    query_type: u16,
    query_class: u16,
    is_acme_challenge: bool,
}

#[derive(Copy, Clone, Debug)]
enum QueryError {
    TooShort,
    TooLong,
    InvalidLabelLength(u8),
    InvalidNameEncoding,
}

impl Query {
    fn size_hint(&self) -> usize {
        self.query_name_bytes.len() +
        2 + // u16 (type)
        2   // u16 (class)
    }

    #[tracing::instrument(skip_all)]
    fn from_bytes(bytes: &[u8], mut cursor: usize) -> Result<(Query, usize), (QueryError, usize)> {
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

        let is_acme_challenge =
            labels.len() > 0 && labels[0].eq_ignore_ascii_case(ACME_CHALLENGE_LABEL);

        let query_type = u16_at(bytes, cursor);
        tracing::trace!(%cursor, %query_type, "parsed query type");
        cursor += 2;

        let query_class = u16_at(bytes, cursor);
        tracing::trace!(%cursor, %query_class, "parsed query class");
        // cursor += 2;

        let mut query_name_bytes = Vec::with_capacity(255);
        let mut query_name_string = String::with_capacity(255);
        for label in labels {
            if !label.is_ascii() {
                return Err((QueryError::InvalidNameEncoding, cursor_at_end));
            }

            let string_label = String::from_utf8(label.to_vec())
                .map_err(|_| (QueryError::InvalidNameEncoding, cursor_at_end))?;
            query_name_string.extend(string_label.chars());
            query_name_string.push('.');

            if query_name_bytes.len() + label.len() + 1 > 255 {
                return Err((QueryError::TooLong, cursor_at_end));
            }
            query_name_bytes.push(label.len() as u8);
            query_name_bytes.extend(label);
        }

        Ok((
            Query {
                query_name_bytes,
                query_name_string,
                query_type,
                query_class,
                is_acme_challenge,
            },
            cursor_at_end,
        ))
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.size_hint());

        bytes.extend(&self.query_name_bytes);
        bytes.extend(&self.query_type.to_be_bytes());
        bytes.extend(&self.query_class.to_be_bytes());

        bytes
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(u8)]
enum RCode {
    NoError = 0,
    FormErr = 1,
    // ServErr = 2,
    NXDomain = 3,
    // NotImpl = 4,
    Refused = 5,
}

#[derive(Clone, Debug)]
struct Answer {
    name: Vec<u8>,
    value: Vec<u8>,
}

impl Answer {
    fn size_hint(&self) -> usize {
        self.name.len() +
        self.value.len() +
        2 + // u16 (type)
        2 + // u16 (class)
        4 + // u32 (ttl)
        2 // u16 (data length)
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.size_hint());

        bytes.extend(&self.name);
        bytes.extend(&TXT_TYPE.to_be_bytes());
        bytes.extend(&IN_CLASS.to_be_bytes());
        bytes.extend(&ANSWER_TTL.to_be_bytes());
        let value_len = self.value.len() as u8;
        let rdata_len = value_len as u16 + 1; // +1 to account for the value_len byte
        bytes.extend(&rdata_len.to_be_bytes());
        bytes.extend(&value_len.to_be_bytes());
        bytes.extend(&self.value);

        bytes
    }
}

#[derive(Clone, Debug)]
struct Response {
    transaction_id: u16,
    rcode: RCode,
    query: Option<Query>,
    answer: Option<Answer>,
}

impl Response {
    fn new() -> Self {
        Response {
            transaction_id: 0,
            rcode: RCode::NoError,
            query: None,
            answer: None,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let answer_len = self
            .answer
            .as_ref()
            .map(|answer| answer.size_hint())
            .unwrap_or(0);
        let query_len = self
            .query
            .as_ref()
            .map(|query| query.size_hint())
            .unwrap_or(0);
        let mut bytes = Vec::with_capacity(12 + query_len + answer_len);

        bytes.extend(&self.transaction_id.to_be_bytes());
        bytes.push(0b10000100); // answer_type | authoritative_response
        bytes.push(0b00100000 | self.rcode as u8); // authentic_data | rcode
        let num_questions = if self.query.is_some() { 1u16 } else { 0u16 };
        bytes.extend(&(num_questions.to_be_bytes()));
        let num_answers = if self.answer.is_some() { 1u16 } else { 0u16 };
        bytes.extend(&(num_answers.to_be_bytes()));
        bytes.extend(&0u16.to_be_bytes()); // number of authority RRs
        bytes.extend(&0u16.to_be_bytes()); // number of additional RRs

        if let Some(query) = &self.query {
            bytes.extend(query.to_bytes());
        }

        if let Some(answer) = &self.answer {
            bytes.extend(answer.to_bytes());
        }

        bytes
    }
}

fn u16_at(bytes: &[u8], pos: usize) -> u16 {
    u16::from_be_bytes([bytes[pos], bytes[pos + 1]])
}

#[tracing::instrument(skip(bytes))]
fn read_label(bytes: &[u8], cursor: usize) -> Result<(&[u8], usize), QueryError> {
    match bytes.get(cursor) {
        Some(&len) if len & 0b11000000 == 0 => {
            tracing::trace!("found label at cursor");
            let (label, new_cursor) = label_at(bytes, cursor)?;
            return Ok((label, new_cursor));
        }
        Some(&off) if off & 0b11000000 == 0b11000000 => {
            let ptr = (u16_at(bytes, cursor) & 0b0011111111111111) as usize;
            tracing::trace!(ptr_offset = %ptr, "found label at pointer");
            if ptr >= cursor {
                return Err(QueryError::InvalidLabelLength(off));
            }
            let (label, _) = label_at(bytes, ptr)?;
            Ok((label, cursor + 2))
        }
        Some(&octet) => return Err(QueryError::InvalidLabelLength(octet)),
        None => return Err(QueryError::TooShort),
    }
}

#[tracing::instrument(skip(bytes))]
fn label_at(bytes: &[u8], mut cursor: usize) -> Result<(&[u8], usize), QueryError> {
    if bytes.len() <= cursor {
        return Err(QueryError::TooShort);
    }

    let label_len = bytes[cursor] as usize;
    tracing::trace!(%cursor, length = %label_len, "parsed label length");
    cursor += 1;

    if cursor + label_len > bytes.len() {
        return Err(QueryError::TooShort);
    }

    let result = &bytes[cursor..(cursor + label_len)];
    cursor += label_len;
    tracing::trace!(new_cursor = %cursor, length = %label_len, "parsed label");

    Ok((result, cursor))
}
