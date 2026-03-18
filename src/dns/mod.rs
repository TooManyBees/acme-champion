mod header;
mod query;
mod response;
mod stream;

const TXT_TYPE: u16 = 16;
const IN_CLASS: u16 = 1;
const ACME_CHALLENGE_LABEL: &[u8] = b"_acme-challenge";
const ACME_CHALLENGE_PREFIX: &'static str = "_acme-challenge.";

use header::{MessageType, OpCode, QueryHeader, QueryHeaderError};
use query::{Query, QueryError};
use response::{Response, ResponseCode};
pub use stream::{Responder, UdpStream};

fn u16_at(bytes: &[u8], pos: usize) -> u16 {
    u16::from_be_bytes([bytes[pos], bytes[pos + 1]])
}

#[derive(Clone, Debug)]
pub enum ReadMessageResult {
    Process {
        response: Response,
        query_name: Vec<u8>,
        challenge_key: String,
    },
    EarlyExit(Response),
    DontRespond,
}

pub fn response_for_message(bytes: &[u8]) -> ReadMessageResult {
    let header = match QueryHeader::from_bytes(bytes) {
        Ok(header) => header,
        Err(QueryHeaderError::TooShort) => {
            tracing::debug!("ignoring malformed message");
            return ReadMessageResult::DontRespond;
        }
    };
    tracing::debug!(?header, "parsed DNS header");

    let mut response = Response::new(&header);

    if header.message_type == MessageType::Reply {
        tracing::debug!("ignoring DNS response");
        return ReadMessageResult::DontRespond;
    }

    if header.opcode != OpCode::Standard {
        tracing::debug!("ignoring non-standard query");
        response.rcode = ResponseCode::Refused;
        return ReadMessageResult::EarlyExit(response);
    }

    if header.num_questions != 1 {
        response.rcode = ResponseCode::FormErr;
        return ReadMessageResult::EarlyExit(response);
    }

    let (query, _cursor) = match Query::from_bytes(&bytes, QueryHeader::LENGTH) {
        Ok(q) => q,
        Err(e) => {
            response.rcode = ResponseCode::FormErr;
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

    if !query.is_txt() {
        tracing::debug!(query_type = %query.query_type, "ignoring non-TXT DNS query");
        response.rcode = ResponseCode::Refused;
        return ReadMessageResult::EarlyExit(response);
    }

    if !query.is_acme_challenge() {
        tracing::debug!(query_name = %query.query_name_string, "ignoring non-acme DNS query");
        response.rcode = ResponseCode::Refused;
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
