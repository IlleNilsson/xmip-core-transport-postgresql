//! What a client sends: the startup message that opens a connection, the
//! password it answers a challenge with, the query it runs, and the
//! goodbye. Read here as well as written, because the far-end
//! [`crate::Session`] reads exactly these.

use std::io::Read;

use transport::error::{Result, protocol_error};

use crate::wire::{Cursor, PROTOCOL_3_0, SSL_REQUEST, cstring, frame, read_body, read_typed};

/// What a client sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frontend {
    SslRequest,
    Startup { user: String, database: String },
    Password(String),
    Query(String),
    Terminate,
}

/// `message` as bytes on the wire.
#[must_use]
pub fn encode_frontend(message: &Frontend) -> Vec<u8> {
    let mut body = Vec::new();
    let kind = match message {
        Frontend::SslRequest => {
            body.extend_from_slice(&SSL_REQUEST.to_be_bytes());
            None
        }
        Frontend::Startup { user, database } => {
            body.extend_from_slice(&PROTOCOL_3_0.to_be_bytes());
            for (name, value) in [("user", user), ("database", database)] {
                cstring(&mut body, name);
                cstring(&mut body, value);
            }
            body.push(0);
            None
        }
        Frontend::Password(password) => {
            cstring(&mut body, password);
            Some(b'p')
        }
        Frontend::Query(sql) => {
            cstring(&mut body, sql);
            Some(b'Q')
        }
        Frontend::Terminate => Some(b'X'),
    };
    frame(kind, &body)
}

/// Read what a client opens with: the startup message, or a request for
/// TLS. `None` when the client closed first.
///
/// # Errors
/// A version that is not 3.0, or a message that breaks off.
pub fn read_startup(reader: &mut impl Read) -> Result<Option<Frontend>> {
    let Some(body) = read_body(reader, None)? else {
        return Ok(None);
    };
    let mut cursor = Cursor::new(&body);
    let version = cursor.int32()?;
    if version == SSL_REQUEST {
        return Ok(Some(Frontend::SslRequest));
    }
    if version != PROTOCOL_3_0 {
        return Err(protocol_error(format!("protocol {version} is not 3.0")));
    }
    let (mut user, mut database) = (String::new(), None);
    loop {
        let name = cursor.cstring()?;
        if name.is_empty() {
            break;
        }
        let value = cursor.cstring()?;
        match name.as_str() {
            "user" => user = value,
            "database" => database = Some(value),
            _ => {}
        }
    }
    Ok(Some(Frontend::Startup {
        database: database.unwrap_or_else(|| user.clone()),
        user,
    }))
}

/// Read one typed message from a client, or `None` when it closed.
///
/// # Errors
/// A type this crate does not read, or a message that breaks off.
pub fn read_frontend(reader: &mut impl Read) -> Result<Option<Frontend>> {
    let Some((kind, body)) = read_typed(reader)? else {
        return Ok(None);
    };
    let mut cursor = Cursor::new(&body);
    Ok(Some(match kind {
        b'p' => Frontend::Password(cursor.cstring()?),
        b'Q' => Frontend::Query(cursor.cstring()?),
        b'X' => Frontend::Terminate,
        other => {
            return Err(protocol_error(format!(
                "{:?} is not a message the simple flow sends",
                char::from(other)
            )));
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_frontend_message_round_trips() {
        let startup = Frontend::Startup {
            user: "xmip".into(),
            database: "orders".into(),
        };
        let bytes = encode_frontend(&startup);
        assert_eq!(
            &bytes[..8],
            &[0, 0, 0, 35, 0, 3, 0, 0],
            "the length counts itself"
        );
        assert_eq!(
            read_startup(&mut bytes.as_slice()).expect("read"),
            Some(startup)
        );
        let ssl = encode_frontend(&Frontend::SslRequest);
        assert_eq!(
            read_startup(&mut ssl.as_slice()).expect("read"),
            Some(Frontend::SslRequest)
        );
        assert!(read_startup(&mut &b""[..]).expect("closed").is_none());
        for message in [
            Frontend::Password("secret".into()),
            Frontend::Query("SELECT 1".into()),
            Frontend::Terminate,
        ] {
            let bytes = encode_frontend(&message);
            assert_eq!(
                read_frontend(&mut bytes.as_slice()).expect("read"),
                Some(message)
            );
        }
        assert!(read_frontend(&mut &b""[..]).expect("closed").is_none());
    }

    #[test]
    fn what_is_not_a_frontend_message_is_refused() {
        assert!(
            read_startup(&mut &[0, 0, 0, 8, 0, 2, 0, 0][..]).is_err(),
            "2.0"
        );
        assert!(read_startup(&mut &[0, 0, 0, 2][..]).is_err(), "under four");
        assert!(
            read_frontend(&mut &[b'B', 0, 0, 0, 4][..]).is_err(),
            "extended flow"
        );
        assert!(
            read_frontend(&mut &[b'Q', 0, 0, 0, 6, b'x'][..]).is_err(),
            "no NUL"
        );
    }
}
