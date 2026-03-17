use super::Challenges;
use hickory_proto::{
    ProtoError,
    op::{Header, LowerQuery, Message, ResponseCode, header::MessageType as HickoryMessageType},
    rr::{rdata::txt::TXT, record_data::RData, record_type::RecordType, resource::Record},
    serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder},
    xfer::{BufDnsStreamHandle, DnsStreamHandle, SerialMessage},
};
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub enum HandleMessageError {
    DontRespond,
    ErrorResponse(Message),
    Malformed(ProtoError),
}

impl From<ProtoError> for HandleMessageError {
    fn from(e: ProtoError) -> Self {
        HandleMessageError::Malformed(e)
    }
}

pub async fn handle_request(
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
