//! The protocol's framing and primitive fields, version 3.0: a type byte,
//! a big-endian length that counts itself, and a body of integers and
//! NUL-terminated strings. The startup message alone has no type byte; the
//! version number opens it instead.
//!
//! What a client sends is in `frontend.rs` and what a server sends is in
//! `backend.rs`; this file is what both are made of — the framing, and the
//! protocol's own fields as [`Postgres`] on codec's byte cursor and
//! [`PostgresWrite`] beside its writer — and the constants the
//! two logins this crate speaks are named by. MD5 and SCRAM are not
//! implemented; a server that asks for either is answered with an error
//! that says so.

use std::io::Read;

use codec::cursor::Cursor;
use codec::writer::ByteWriter;
use transport::error::{Result, classify, protocol_error};

/// Version 3.0, as the startup message writes it.
pub const PROTOCOL_3_0: i32 = 196_608;
/// The request for TLS a client may open with; answered `N` here.
pub const SSL_REQUEST: i32 = 80_877_103;
/// The most one message may be.
pub const MAX_MESSAGE: usize = 64 * 1024 * 1024;

/// Authentication is done.
pub const AUTH_OK: i32 = 0;
/// Send the password as it is.
pub const AUTH_CLEARTEXT: i32 = 3;
/// Send the password hashed with MD5 and a salt. Not implemented.
pub const AUTH_MD5: i32 = 5;
/// Begin SASL, which is SCRAM. Not implemented.
pub const AUTH_SASL: i32 = 10;

/// A type byte where there is one, then the length and body.
#[must_use]
pub fn frame(kind: Option<u8>, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 5);
    if let Some(kind) = kind {
        out.byte(kind);
    }
    out.length(body.len() + 4).bytes(body);
    out
}

/// A typed message: its type byte and body, or `None` when the peer closed.
///
/// # Errors
/// A read that failed, a length under four or over [`MAX_MESSAGE`].
pub fn read_typed(reader: &mut impl Read) -> Result<Option<(u8, Vec<u8>)>> {
    let mut kind = [0u8];
    let read = reader
        .read(&mut kind)
        .map_err(|e| classify("reading a message type", &e))?;
    if read == 0 {
        return Ok(None);
    }
    read_body(reader, Some(kind[0])).map(|body| body.map(|b| (kind[0], b)))
}

/// The body behind a length, the length counting itself. Where `kind` is
/// `None` this is the startup and a closed connection is `None`.
///
/// # Errors
/// A read that failed, a length under four or over [`MAX_MESSAGE`].
pub fn read_body(reader: &mut impl Read, kind: Option<u8>) -> Result<Option<Vec<u8>>> {
    let mut length = [0u8; 4];
    if kind.is_none() {
        let first = reader
            .read(&mut length[..1])
            .map_err(|e| classify("reading a message length", &e))?;
        if first == 0 {
            return Ok(None);
        }
        reader
            .read_exact(&mut length[1..])
            .map_err(|e| classify("reading a message length", &e))?;
    } else {
        reader
            .read_exact(&mut length)
            .map_err(|e| classify("reading a message length", &e))?;
    }
    let length = usize::try_from(i32::from_be_bytes(length))
        .ok()
        .and_then(|l| l.checked_sub(4))
        .ok_or_else(|| protocol_error("a message length under four"))?;
    if length > MAX_MESSAGE {
        return Err(protocol_error("a message over what Xmip will read"));
    }
    let mut body = vec![0u8; length];
    reader
        .read_exact(&mut body)
        .map_err(|e| classify("reading a message body", &e))?;
    Ok(Some(body))
}

/// The protocol's own fields, read off codec's cursor. Integers are codec's,
/// big-endian (`i32_be`).
pub trait Postgres {
    /// The next i16 count, negative read as zero.
    ///
    /// # Errors
    /// Fewer than two bytes remain.
    fn count(&mut self) -> Result<usize>;

    /// The next NUL-terminated string, lossily UTF-8.
    ///
    /// # Errors
    /// No NUL before the end.
    fn cstring(&mut self) -> Result<String>;
}

impl Postgres for Cursor<'_> {
    fn count(&mut self) -> Result<usize> {
        Ok(usize::try_from(self.i16_be()?).unwrap_or(0))
    }

    fn cstring(&mut self) -> Result<String> {
        Ok(String::from_utf8_lossy(self.take_until(0)?).into_owned())
    }
}

/// The protocol's own fields, written beside codec's writer.
pub trait PostgresWrite {
    /// `text` followed by the NUL that ends a wire string.
    fn cstring(&mut self, text: &str) -> &mut Self;

    /// `count` as the wire's i16, saturating.
    fn count(&mut self, count: usize) -> &mut Self;

    /// `length` as the wire's i32, saturating.
    fn length(&mut self, length: usize) -> &mut Self;
}

impl PostgresWrite for Vec<u8> {
    fn cstring(&mut self, text: &str) -> &mut Self {
        self.bytes(text.as_bytes()).byte(0)
    }

    fn count(&mut self, count: usize) -> &mut Self {
        self.i16_be(i16::try_from(count).unwrap_or(i16::MAX))
    }

    fn length(&mut self, length: usize) -> &mut Self {
        self.i32_be(i32::try_from(length).unwrap_or(i32::MAX))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_carries_its_length_and_a_body_reads_its_fields() {
        let framed = frame(Some(b'Q'), b"SELECT 1\0");
        assert_eq!(
            &framed[..5],
            &[b'Q', 0, 0, 0, 13],
            "the length counts itself"
        );
        let (kind, body) = read_typed(&mut framed.as_slice())
            .expect("read")
            .expect("one");
        assert_eq!(kind, b'Q');
        let mut cursor = Cursor::new(&body);
        assert_eq!(cursor.cstring().expect("sql"), "SELECT 1");
        assert!(read_typed(&mut &b""[..]).expect("closed").is_none());

        let mut body = Vec::new();
        body.cstring("id").count(3).length(70_000).byte(b'Z');
        let mut cursor = Cursor::new(&body);
        assert_eq!(cursor.cstring().expect("name"), "id");
        assert_eq!(cursor.count().expect("i16"), 3);
        assert_eq!(cursor.i32_be().expect("i32"), 70_000);
        assert_eq!(cursor.byte().expect("byte"), b'Z');
        let error = cursor.byte().expect_err("past the end");
        assert!(error.message.contains("runs past"), "{}", error.message);
    }

    #[test]
    fn a_length_that_is_not_a_message_is_refused() {
        assert!(
            read_body(&mut &[0, 0, 0, 2][..], None).is_err(),
            "under four"
        );
        assert!(
            read_body(&mut &[0x7f, 0, 0, 0][..], Some(b'R')).is_err(),
            "over what Xmip will read"
        );
        assert!(
            read_body(&mut &[0, 0, 0, 8, 1][..], Some(b'R')).is_err(),
            "breaks off"
        );
        assert!(read_body(&mut &b""[..], None).expect("closed").is_none());
        assert!(Cursor::new(b"no NUL").cstring().is_err());
    }
}
