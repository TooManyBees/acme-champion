mod header;
mod query;
mod response;

const A_TYPE: u16 = 1;
const NS_TYPE: u16 = 2;
const SOA_TYPE: u16 = 6;
const TXT_TYPE: u16 = 16;
const AAAA_TYPE: u16 = 28;
const ACME_CHALLENGE_LABEL: &[u8] = b"_acme-challenge";

use header::{MessageType, OpCode, QueryHeader, QueryHeaderError};
use query::{Query, QueryError};
use response::{Response, ResponseCode};

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
    A = A_TYPE,
    NS = NS_TYPE,
    SOA = SOA_TYPE,
    TXT = TXT_TYPE,
    AAAA = AAAA_TYPE,
}

pub fn response_for_message(bytes: &[u8]) -> ReadMessageResult {
    let header = match QueryHeader::from_bytes(bytes) {
        Ok(header) => header,
        Err(QueryHeaderError::TooShort) => {
            log::debug!("ignoring malformed message");
            return ReadMessageResult::DontRespond;
        }
    };
    log::trace!(header:? = header; "parsed DNS header");

    let mut response = Response::new(&header);

    if header.message_type == MessageType::Reply {
        log::debug!(id = header.transaction_id; "ignoring DNS response");
        return ReadMessageResult::DontRespond;
    }

    if header.opcode != OpCode::Standard {
        log::debug!(
            id = header.transaction_id,
            opcode:? = header.opcode;
            "ignoring non-standard query",
        );
        response.rcode = ResponseCode::Refused;
        return ReadMessageResult::EarlyExit(response);
    }

    if header.num_questions != 1 {
        log::debug!(
            id = header.transaction_id,
            num_questions = header.num_questions;
            "ignoring query with more or less than 1 question",
        );
        response.rcode = ResponseCode::FormErr;
        return ReadMessageResult::EarlyExit(response);
    }

    let (query, _cursor) = match Query::from_bytes(&bytes, QueryHeader::LENGTH) {
        Ok(q) => q,
        Err(e) => {
            response.rcode = ResponseCode::FormErr;
            match e {
                (QueryError::TooShort, _) => {
                    log::debug!("query label length exceeds message size");
                }
                (QueryError::TooLong, _) => {
                    log::debug!("query name size exceeds maximum length of 255");
                }
                (QueryError::InvalidLabelLength(octet), _) => {
                    log::debug!(octet; "query label length octet is malformed");
                }
                (QueryError::InvalidNameEncoding, _) => {
                    log::debug!("query label is not valid ASCII");
                }
            }
            return ReadMessageResult::EarlyExit(response);
        }
    };

    response.query = Some(query.clone());

    let query_type = match query.query_type {
        A_TYPE => ValidQueryType::A,
        TXT_TYPE => ValidQueryType::TXT,
        SOA_TYPE => ValidQueryType::SOA,
        NS_TYPE => ValidQueryType::NS,
        AAAA_TYPE => ValidQueryType::AAAA,
        query_type => {
            log::debug!(
                id = header.transaction_id,
                query_type;
                "ignoring non-TXT/NS DNS query",
            );
            response.rcode = ResponseCode::Refused;
            return ReadMessageResult::EarlyExit(response);
        }
    };

    if !query.is_acme_challenge() {
        log::debug!(
            id = header.transaction_id,
            query_name:% = query.query_name_string;
            "ignoring non-acme DNS query");
        response.rcode = ResponseCode::Refused;
        return ReadMessageResult::EarlyExit(response);
    }

    log::debug!(
        id = response.transaction_id,
        query_type:? = query_type,
        name:% = query.query_name_string;
        "received valid query",
    );

    ReadMessageResult::Process {
        response,
        query_name: query.query_name_bytes,
        query_type,
        challenge_key: query.query_name_string,
    }
}
