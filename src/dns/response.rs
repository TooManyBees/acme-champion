use super::{IN_CLASS, Query, QueryHeader, TXT_TYPE};

#[derive(Clone, Debug)]
pub struct Response {
    pub transaction_id: u16,
    pub recursion_desired: bool,
    pub rcode: ResponseCode,
    pub query: Option<Query>,
    pub answer: Option<Answer>,
}

impl Response {
    pub fn new(header: &QueryHeader) -> Self {
        Response {
            transaction_id: header.transaction_id,
            recursion_desired: header.recursion_desired,
            rcode: ResponseCode::NoError,
            query: None,
            answer: None,
        }
    }

    pub fn set_rcode_noerror(&mut self) {
        self.rcode = ResponseCode::NoError;
    }

    pub fn set_rcode_nxdomain(&mut self) {
        self.rcode = ResponseCode::NXDomain;
    }

    pub fn set_answer(&mut self, name: Vec<u8>, value: &str) {
        self.answer = Some(Answer {
            name,
            value: value.to_string().into_bytes(),
        });
    }

    pub fn to_bytes(&self) -> Vec<u8> {
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
        let recursion_desired = if self.recursion_desired { 1u8 } else { 0u8 };
        bytes.push(0b10000100 | recursion_desired); // answer_type | authoritative_response | recursion_desired
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

#[derive(Copy, Clone, Debug)]
#[repr(u8)]
pub enum ResponseCode {
    NoError = 0,
    FormErr = 1,
    // ServErr = 2,
    NXDomain = 3,
    // NotImpl = 4,
    Refused = 5,
}

const ANSWER_TTL: u32 = 30;

#[derive(Clone, Debug)]
pub struct Answer {
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
