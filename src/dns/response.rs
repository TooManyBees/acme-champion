use super::{Query, QueryHeader, ValidQueryType};
use std::net::{Ipv4Addr, Ipv6Addr};

const IN_CLASS: u16 = 1;

#[derive(Clone, Debug)]
pub struct Response {
    pub transaction_id: u16,
    pub recursion_desired: bool,
    pub rcode: ResponseCode,
    pub query: Option<Query>,
    pub answers: Vec<Answer>,
}

impl Response {
    pub fn new(header: &QueryHeader) -> Self {
        Response {
            transaction_id: header.transaction_id,
            recursion_desired: header.recursion_desired,
            rcode: ResponseCode::NoError,
            query: None,
            answers: Vec::with_capacity(1),
        }
    }

    pub fn set_rcode_noerror(&mut self) {
        self.rcode = ResponseCode::NoError;
    }

    pub fn set_rcode_nxdomain(&mut self) {
        self.rcode = ResponseCode::NXDomain;
    }

    pub fn add_a_answer(&mut self, name: Vec<u8>, ip: Ipv4Addr) {
        self.answers.push(Answer {
            name,
            query_type: ValidQueryType::A,
            value: ip.to_bits().to_be_bytes().to_vec(),
        });
    }

    pub fn add_aaaa_answer(&mut self, name: Vec<u8>, ip: Ipv6Addr) {
        self.answers.push(Answer {
            name,
            query_type: ValidQueryType::AAAA,
            value: ip.to_bits().to_be_bytes().to_vec(),
        });
    }

    pub fn add_txt_answer(&mut self, name: Vec<u8>, value: String) {
        let value_len = value.len() as u8;
        let mut value_bytes = Vec::with_capacity(value.len() + 1);
        value_bytes.extend(&value_len.to_be_bytes());
        value_bytes.extend(&value.into_bytes());

        self.answers.push(Answer {
            name,
            query_type: ValidQueryType::TXT,
            value: value_bytes,
        })
    }

    pub fn add_ns_answer(&mut self, name: Vec<u8>) {
        let label_len = name[0] as usize;
        let value = name[(label_len + 1)..].to_vec();
        self.answers.push(Answer {
            name: name.clone(),
            query_type: ValidQueryType::NS,
            value,
        })
    }

    pub fn add_soa_answer(&mut self, name: Vec<u8>) {
        let mut value = Vec::with_capacity(name.len() * 2 + std::mem::size_of::<u32>() * 5);
        value.extend(&name); // mname
        value.extend(&name); // rname
        value.extend(1u32.to_be_bytes()); // serial
        value.extend(10800u32.to_be_bytes()); // refresh
        value.extend(3600u32.to_be_bytes()); // retry
        value.extend(604800u32.to_be_bytes()); // expire
        value.extend(30u32.to_be_bytes()); // minimum
        self.answers.push(Answer {
            name: name.clone(),
            query_type: ValidQueryType::SOA,
            value,
        });
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let answer_len: usize = self.answers.iter().map(|answer| answer.size_hint()).sum();
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
        let num_answers = self.answers.len() as u16;
        bytes.extend(&num_answers.to_be_bytes());
        bytes.extend(&0u16.to_be_bytes()); // number of authority RRs
        bytes.extend(&0u16.to_be_bytes()); // number of additional RRs

        if let Some(query) = &self.query {
            bytes.extend(query.to_bytes());
        }

        for answer in &self.answers {
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
    query_type: ValidQueryType,
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
        bytes.extend(&(self.query_type as u16).to_be_bytes());
        bytes.extend(&IN_CLASS.to_be_bytes());
        bytes.extend(&ANSWER_TTL.to_be_bytes());
        bytes.extend(&(self.value.len() as u16).to_be_bytes());
        bytes.extend(&self.value);

        bytes
    }
}
