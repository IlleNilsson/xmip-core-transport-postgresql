//! What a server sends: the authentication challenge or its absence, the
//! parameters and key it reports at login, the description and rows a
//! query answers with, the tag that completes it, and an error. Written
//! here as well as read, because the far-end [`crate::Session`] writes
//! exactly these.

use std::io::Read;

use codec::cursor::Cursor;
use codec::writer::ByteWriter;
use transport::error::Result;

use crate::wire::{Postgres, PostgresWrite, frame, read_typed};

/// What a server sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Backend {
    /// One of the `AUTH_*` methods, or done.
    Authentication(i32),
    ParameterStatus {
        name: String,
        value: String,
    },
    BackendKeyData {
        process: i32,
        secret: i32,
    },
    /// `I` idle, `T` in a transaction, `E` in a failed one.
    ReadyForQuery(u8),
    /// The columns of the rows to come.
    RowDescription(Vec<String>),
    /// One row, each column text or NULL.
    DataRow(Vec<Option<String>>),
    /// `SELECT 3`, `INSERT 0 1`.
    CommandComplete(String),
    EmptyQueryResponse,
    ErrorResponse {
        severity: String,
        code: String,
        message: String,
    },
    /// A message this crate reads past: a notice, a notification.
    Other(u8),
}

/// `message` as bytes on the wire.
#[must_use]
pub fn encode_backend(message: &Backend) -> Vec<u8> {
    let mut body = Vec::new();
    let kind = match message {
        Backend::Authentication(method) => {
            body.i32_be(*method);
            b'R'
        }
        Backend::ParameterStatus { name, value } => {
            body.cstring(name).cstring(value);
            b'S'
        }
        Backend::BackendKeyData { process, secret } => {
            body.i32_be(*process).i32_be(*secret);
            b'K'
        }
        Backend::ReadyForQuery(status) => {
            body.push(*status);
            b'Z'
        }
        Backend::RowDescription(columns) => {
            body.count(columns.len());
            for column in columns {
                body.cstring(column)
                    .i32_be(0) // table
                    .i16_be(0) // attribute
                    .i32_be(25) // text
                    .i16_be(-1) // varlena
                    .i32_be(-1) // no modifier
                    .i16_be(0); // text format
            }
            b'T'
        }
        Backend::DataRow(values) => {
            body.count(values.len());
            for value in values {
                match value {
                    Some(text) => body.length(text.len()).bytes(text.as_bytes()),
                    None => body.i32_be(-1),
                };
            }
            b'D'
        }
        Backend::CommandComplete(tag) => {
            body.cstring(tag);
            b'C'
        }
        Backend::EmptyQueryResponse => b'I',
        Backend::ErrorResponse {
            severity,
            code,
            message,
        } => {
            for (field, value) in [
                (b'S', severity),
                (b'V', severity),
                (b'C', code),
                (b'M', message),
            ] {
                body.push(field);
                body.cstring(value);
            }
            body.push(0);
            b'E'
        }
        Backend::Other(kind) => *kind,
    };
    frame(Some(kind), &body)
}

/// Read one message from a server, or `None` when it closed.
///
/// # Errors
/// A message that breaks off.
pub fn read_backend(reader: &mut impl Read) -> Result<Option<Backend>> {
    let Some((kind, body)) = read_typed(reader)? else {
        return Ok(None);
    };
    let mut cursor = Cursor::new(&body);
    Ok(Some(match kind {
        b'R' => Backend::Authentication(cursor.i32_be()?),
        b'S' => Backend::ParameterStatus {
            name: cursor.cstring()?,
            value: cursor.cstring()?,
        },
        b'K' => Backend::BackendKeyData {
            process: cursor.i32_be()?,
            secret: cursor.i32_be()?,
        },
        b'Z' => Backend::ReadyForQuery(cursor.byte()?),
        b'T' => {
            let count = cursor.count()?;
            let mut columns = Vec::with_capacity(count);
            for _ in 0..count {
                columns.push(cursor.cstring()?);
                cursor.skip(18)?;
            }
            Backend::RowDescription(columns)
        }
        b'D' => {
            let count = cursor.count()?;
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
                let length = cursor.i32_be()?;
                values.push(if length < 0 {
                    None
                } else {
                    let bytes = cursor.take(usize::try_from(length).unwrap_or(0))?;
                    Some(String::from_utf8_lossy(bytes).into_owned())
                });
            }
            Backend::DataRow(values)
        }
        b'C' => Backend::CommandComplete(cursor.cstring()?),
        b'I' => Backend::EmptyQueryResponse,
        b'E' => {
            let (mut severity, mut code, mut message) =
                (String::new(), String::new(), String::new());
            loop {
                let field = cursor.byte()?;
                if field == 0 {
                    break;
                }
                let value = cursor.cstring()?;
                match field {
                    b'S' => severity = value,
                    b'C' => code = value,
                    b'M' => message = value,
                    _ => {}
                }
            }
            Backend::ErrorResponse {
                severity,
                code,
                message,
            }
        }
        other => Backend::Other(other),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::AUTH_CLEARTEXT;

    #[test]
    fn every_backend_message_round_trips() {
        for message in [
            Backend::Authentication(AUTH_CLEARTEXT),
            Backend::ParameterStatus {
                name: "server_version".into(),
                value: "16.0".into(),
            },
            Backend::BackendKeyData {
                process: 42,
                secret: -7,
            },
            Backend::ReadyForQuery(b'I'),
            Backend::RowDescription(vec!["id".into(), "payload".into()]),
            Backend::DataRow(vec![Some("1".into()), None, Some(String::new())]),
            Backend::CommandComplete("INSERT 0 1".into()),
            Backend::EmptyQueryResponse,
            Backend::ErrorResponse {
                severity: "FATAL".into(),
                code: "28P01".into(),
                message: "password authentication failed".into(),
            },
            Backend::Other(b'N'),
        ] {
            let bytes = encode_backend(&message);
            assert_eq!(
                read_backend(&mut bytes.as_slice()).expect("read"),
                Some(message)
            );
        }
        assert!(read_backend(&mut &b""[..]).expect("closed").is_none());
    }

    #[test]
    fn what_is_not_a_backend_message_is_refused() {
        assert!(
            read_backend(&mut &[b'R', 0, 0, 0, 8, 0][..]).is_err(),
            "short"
        );
        assert!(
            read_backend(&mut &[b'R', 0x7f, 0, 0, 0][..]).is_err(),
            "too big"
        );
        assert!(
            read_backend(&mut &[b'C', 0, 0, 0, 6, b'x', b'y'][..]).is_err(),
            "a tag with no NUL"
        );
    }
}
