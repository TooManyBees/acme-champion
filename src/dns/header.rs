use super::u16_at;

#[derive(Copy, Clone, Debug)]
pub enum QueryHeaderError {
    TooShort,
}

#[derive(Copy, Clone, Debug)]
pub struct QueryHeader {
    pub(super) transaction_id: u16,
    pub message_type: MessageType,
    pub(super) recursion_desired: bool,
    pub opcode: OpCode,
    pub num_questions: u16,
}

impl QueryHeader {
    pub const LENGTH: usize = 12;

    pub fn from_bytes(bytes: &[u8]) -> Result<QueryHeader, QueryHeaderError> {
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

        let recursion_desired = bytes[2] & 0b00000001 == 1;

        let num_questions = u16_at(bytes, 4);

        let header = QueryHeader {
            transaction_id,
            message_type,
            recursion_desired,
            opcode,
            num_questions,
        };

        Ok(header)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MessageType {
    Query,
    Reply,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum OpCode {
    Standard,
    Inverse,
    Status,
    Other,
}
