use super::{ACME_CHALLENGE_LABEL, u16_at};

#[derive(Clone, Debug)]
pub struct Query {
    pub query_name_bytes: Vec<u8>,
    pub query_name_string: String,
    pub query_type: u16,
    pub query_class: u16,
    pub is_acme_challenge: bool,
}

#[derive(Copy, Clone, Debug)]
pub enum QueryError {
    TooShort,
    TooLong,
    InvalidLabelLength(u8),
    InvalidNameEncoding,
}

impl Query {
    pub fn size_hint(&self) -> usize {
        self.query_name_bytes.len() +
        2 + // u16 (type)
        2 // u16 (class)
    }

    pub fn from_bytes(
        bytes: &[u8],
        mut cursor: usize,
    ) -> Result<(Query, usize), (QueryError, usize)> {
        let mut labels = vec![];
        while cursor < bytes.len() {
            let (label, new_cursor) = read_label(bytes, cursor).map_err(|e| (e, 0))?;
            labels.push(label);
            cursor = new_cursor;
            if label.len() == 0 {
                break;
            }
        }
        log::trace!(num_labels:% = labels.len(); "parsed query labels");

        let cursor_at_end = cursor + 4;

        let is_acme_challenge =
            labels.len() > 0 && labels[0].eq_ignore_ascii_case(ACME_CHALLENGE_LABEL);

        let query_type = u16_at(bytes, cursor);
        log::trace!(cursor, query_type; "parsed query type");
        cursor += 2;

        let query_class = u16_at(bytes, cursor);
        log::trace!(cursor, query_class; "parsed query class");
        // cursor += 2;

        let mut query_name_bytes = Vec::with_capacity(255);
        let mut query_name_string = String::with_capacity(255);
        for label in labels {
            if !label.is_ascii() {
                return Err((QueryError::InvalidNameEncoding, cursor_at_end));
            }

            let string_label = String::from_utf8(label.to_vec())
                .map_err(|_| (QueryError::InvalidNameEncoding, cursor_at_end))?;
            if !query_name_string.is_empty() && !string_label.is_empty() {
                query_name_string.push('.');
            }
            query_name_string.extend(string_label.chars());

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

    pub fn is_acme_challenge(&self) -> bool {
        self.is_acme_challenge
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.size_hint());

        bytes.extend(&self.query_name_bytes);
        bytes.extend(&self.query_type.to_be_bytes());
        bytes.extend(&self.query_class.to_be_bytes());

        bytes
    }
}

fn read_label(bytes: &[u8], cursor: usize) -> Result<(&[u8], usize), QueryError> {
    match bytes.get(cursor) {
        Some(&len) if len & 0b11000000 == 0 => {
            log::trace!("found label at cursor");
            let (label, new_cursor) = label_at(bytes, cursor)?;
            return Ok((label, new_cursor));
        }
        Some(&off) if off & 0b11000000 == 0b11000000 => {
            let ptr = (u16_at(bytes, cursor) & 0b0011111111111111) as usize;
            log::trace!(ptr_offset = ptr; "found label at pointer");
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

fn label_at(bytes: &[u8], mut cursor: usize) -> Result<(&[u8], usize), QueryError> {
    if bytes.len() <= cursor {
        return Err(QueryError::TooShort);
    }

    let label_len = bytes[cursor] as usize;
    log::trace!(cursor, length = label_len; "parsed label length");
    cursor += 1;

    if cursor + label_len > bytes.len() {
        return Err(QueryError::TooShort);
    }

    let result = &bytes[cursor..(cursor + label_len)];
    cursor += label_len;
    log::trace!(new_cursor = cursor, length = label_len; "parsed label");

    Ok((result, cursor))
}
