mod header;
mod query;
mod response;
mod stream;

const NS_TYPE: u16 = 2;
const TXT_TYPE: u16 = 16;
const ACME_CHALLENGE_LABEL: &[u8] = b"_acme-challenge";

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
        query_type: ValidQueryType,
        challenge_key: String,
    },
    EarlyExit(Response),
    DontRespond,
}

#[derive(Copy, Clone, Debug)]
#[repr(u16)]
pub enum ValidQueryType {
    NS = 2,
    TXT = 16,
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

    let query_type = match query.query_type {
        TXT_TYPE => ValidQueryType::TXT,
        NS_TYPE => ValidQueryType::NS,
        query_type => {
            tracing::debug!(%query_type, "ignoring non-TXT/NS DNS query");
            response.rcode = ResponseCode::Refused;
            return ReadMessageResult::EarlyExit(response);
        }
    };

    if !query.is_acme_challenge() {
        tracing::debug!(query_name = %query.query_name_string, "ignoring non-acme DNS query");
        response.rcode = ResponseCode::Refused;
        return ReadMessageResult::EarlyExit(response);
    }

    ReadMessageResult::Process {
        response,
        query_name: query.query_name_bytes,
        query_type,
        challenge_key: query.query_name_string,
    }
}
