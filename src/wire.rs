//! The protocol's framing and primitive fields, version 3.0: a type byte,
//! a big-endian length that counts itself, and a body of integers and
//! NUL-terminated strings. The startup message alone has no type byte; the
//! version number opens it instead.
//!
//! What a client sends is in `frontend.rs` and what a server sends is in
//! `backend.rs`; this file is what both are made of, and the constants the
//! two logins this crate speaks are named by. MD5 and SCRAM are not
//! implemented; a server that asks for either is answered with an error
//! that says so.

use std::io::Read;

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
        out.push(kind);
    }
    out.extend_from_slice(&int32(body.len() + 4).to_be_bytes());
    out.extend_from_slice(body);
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

/// `text` followed by the NUL that ends a wire string.
pub fn cstring(out: &mut Vec<u8>, text: &str) {
    out.extend_from_slice(text.as_bytes());
    out.push(0);
}

/// `count` as the wire's i16, saturating.
#[must_use]
pub fn int16(count: usize) -> i16 {
    i16::try_from(count).unwrap_or(i16::MAX)
}

/// `count` as the wire's i32, saturating.
#[must_use]
pub fn int32(count: usize) -> i32 {
    i32::try_from(count).unwrap_or(i32::MAX)
}

/// Reads a body's fields in order.
pub struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    /// A cursor at the start of `bytes`.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    /// The next `count` bytes.
    ///
    /// # Errors
    /// Fewer than `count` bytes remain.
    pub fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(count)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| protocol_error("a field that runs past the message"))?;
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }

    /// Past the next `count` bytes.
    ///
    /// # Errors
    /// Fewer than `count` bytes remain.
    pub fn skip(&mut self, count: usize) -> Result<()> {
        self.take(count).map(|_| ())
    }

    /// The next byte.
    ///
    /// # Errors
    /// Nothing remains.
    pub fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// The next i16, negative read as zero.
    ///
    /// # Errors
    /// Fewer than two bytes remain.
    pub fn int16(&mut self) -> Result<usize> {
        let b = self.take(2)?;
        Ok(usize::try_from(i16::from_be_bytes([b[0], b[1]])).unwrap_or(0))
    }

    /// The next i32.
    ///
    /// # Errors
    /// Fewer than four bytes remain.
    pub fn int32(&mut self) -> Result<i32> {
        let b = self.take(4)?;
        Ok(i32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// The next NUL-terminated string, lossily UTF-8.
    ///
    /// # Errors
    /// No NUL before the end.
    pub fn cstring(&mut self) -> Result<String> {
        let end = self.bytes[self.at..]
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(|| protocol_error("a string that never ends"))?;
        let text = String::from_utf8_lossy(self.take(end)?).into_owned();
        self.skip(1)?;
        Ok(text)
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
        cstring(&mut body, "id");
        body.extend_from_slice(&int16(3).to_be_bytes());
        body.extend_from_slice(&int32(70_000).to_be_bytes());
        body.push(b'Z');
        let mut cursor = Cursor::new(&body);
        assert_eq!(cursor.cstring().expect("name"), "id");
        assert_eq!(cursor.int16().expect("i16"), 3);
        assert_eq!(cursor.int32().expect("i32"), 70_000);
        assert_eq!(cursor.byte().expect("byte"), b'Z');
        assert!(cursor.byte().is_err(), "past the end");
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
