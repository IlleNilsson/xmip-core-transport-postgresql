#![forbid(unsafe_code)]

//! Streams that arrive as rows. One row is one Stream: the last column of
//! a configured query is what Xmip carries, the first column is where it
//! came from.
//!
//! `PostgreSQL` is the database the estate's partners already have, and a
//! table in it is the oldest integration surface there is: a producer
//! inserts, an integrator polls. A Receive Location runs its query — `SELECT
//! id, payload FROM inbox ORDER BY id` unless told otherwise — and hands
//! each row up; a Send Location inserts the Stream as one column of one
//! row — as text when the Stream is UTF-8 without a NUL, in the bytea hex
//! form otherwise, and a value in that form is the bytes again on the way
//! back (`bytea.rs`). What is spoken is the frontend/backend protocol, version 3.0, in
//! its simple query flow, on port 5432: startup, trust or a cleartext
//! password, `Query`, rows as text, `Terminate`. MD5 and SCRAM are not
//! implemented and a server that asks for them is told so; TLS is the
//! transport capability's, per ADR-0033.
//!
//! Rows are artefacts and this transport claims none of them, per ADR-0024:
//! the atomic claim a database has, `SELECT … FOR UPDATE SKIP LOCKED`, only
//! holds inside a transaction, and the simple flow here opens and closes
//! its connection inside one receive, so there is no transaction to hold
//! it across the Stream's lifetime. Until the claim is written, a Receive
//! Location is one consumer of its query, and the query itself — a status
//! column, a `DELETE … RETURNING` — is what keeps a row from arriving twice.
//!
//! The origin URI carries what the row knew:
//! `postgresql://server/orders?row=41`. A send target is
//! `postgresql://host:5432/<database>/<table>/<column>`,
//! `host:5432/<database>/<table>/<column>`, or `<table>/<column>` on the
//! configured server and database.

pub mod backend;
pub mod bytea;
pub mod client;
pub mod frontend;
pub mod session;
pub mod wire;

use std::net::TcpListener;
use std::time::Duration;

pub use client::{Client, QueryResult, quote_identifier, quote_literal};
pub use session::{Answer, Event, Session};
use transport::claim::{NoNativeClaim, ResourceClaim};
use transport::error::{Result, TransportError, protocol_error};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::socket;
use transport::{Arrived, Directions, Transport};

/// What a Receive Location runs unless told otherwise.
pub const DEFAULT_QUERY: &str = "SELECT id, payload FROM inbox ORDER BY id";

/// What the loopback pair agrees on: one user logged in by trust to one
/// database, one table and column the payload is inserted into.
const LOOPBACK_USER: &str = "probe";
const LOOPBACK_DATABASE: &str = "probe";
const LOOPBACK_TARGET: &str = "probe/payload";

#[derive(Clone)]
pub struct PostgresTransport {
    server: String,
    user: String,
    database: String,
    password: Option<String>,
    query: String,
    timeout: Option<Duration>,
}

impl PostgresTransport {
    /// Speak to the server at `server` as `user` on `database`.
    #[must_use]
    pub fn new(
        server: impl Into<String>,
        user: impl Into<String>,
        database: impl Into<String>,
    ) -> Self {
        Self {
            server: server.into(),
            user: user.into(),
            database: database.into(),
            password: None,
            query: DEFAULT_QUERY.to_string(),
            timeout: None,
        }
    }

    /// The password to give when the server asks for one in the clear.
    #[must_use]
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// The query a receive runs: the first column is the row's name, the
    /// last is the Stream.
    #[must_use]
    pub fn querying(mut self, query: impl Into<String>) -> Self {
        self.query = query.into();
        self
    }

    /// Give up on a server that stops mid-message.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Log in to the server.
    ///
    /// # Errors
    /// Where the server could not be reached or refused the login.
    pub fn connect(&self) -> Result<Client> {
        self.connect_to(&self.server, &self.database)
    }

    fn connect_to(&self, server: &str, database: &str) -> Result<Client> {
        Client::connect(
            server,
            &self.user,
            database,
            self.password.as_deref(),
            self.timeout,
        )
    }

    /// Bind as the far end clients connect to, and report the address.
    ///
    /// # Errors
    /// Where the address is taken, malformed, or not permitted.
    pub fn bind(&self) -> Result<(TcpListener, String)> {
        socket::bind_tcp(&self.server)
    }

    /// Accept one client on an already-bound listener, demanding this
    /// transport's password where it has one.
    ///
    /// # Errors
    /// Where the connection could not be accepted or the login failed.
    pub fn accept_one(&self, listener: &TcpListener) -> Result<Session> {
        Session::accept(listener, self.password.as_deref(), self.timeout)
    }

    /// Where a target names the server, database, table and column, or
    /// some suffix of them on what this transport is configured with.
    fn resolve<'a>(&'a self, target: &'a str) -> Result<(&'a str, &'a str, &'a str, &'a str)> {
        let (server, path) = socket::target("postgresql", target)
            .or_else(|| socket::target("postgres", target))
            .or_else(|| match target.split_once('/') {
                Some((peer, path)) if peer.contains(':') => Some((peer, path)),
                _ => None,
            })
            .unwrap_or((&self.server, target));
        let segments: Vec<&str> = path.split('/').collect();
        match segments.as_slice() {
            [database, table, column] => Ok((server, database, table, column)),
            [table, column] => Ok((server, &self.database, table, column)),
            _ => Err(TransportError::permanent(format!(
                "{target:?} is not database/table/column or table/column"
            ))),
        }
    }
}

impl Transport for PostgresTransport {
    fn name(&self) -> &'static str {
        "postgresql"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    /// Run the query; each row is a Stream.
    fn receive(&self) -> Result<Vec<Arrived>> {
        let mut client = self.connect()?;
        let result = client.query(&self.query)?;
        client.close()?;
        let mut arrived = Vec::with_capacity(result.rows.len());
        for (index, row) in result.rows.into_iter().enumerate() {
            let name = row
                .first()
                .cloned()
                .flatten()
                .unwrap_or_else(|| index.to_string());
            let value = row.last().cloned().flatten().unwrap_or_default();
            arrived.push(Arrived::new(
                format!("postgresql://{}/{}?row={name}", self.server, self.database),
                bytea::column_bytes(value),
            ));
        }
        Ok(arrived)
    }

    /// Insert the bytes as one column of one row: text as text, anything
    /// else in the bytea hex form.
    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        let (server, database, table, column) = self.resolve(target)?;
        let literal = match std::str::from_utf8(bytes) {
            Ok(text) if bytea::is_text(bytes) => quote_literal(text),
            _ => quote_literal(&bytea::hex_literal(bytes)),
        };
        let mut client = self.connect_to(server, database)?;
        let sql = format!(
            "INSERT INTO {} ({}) VALUES ({})",
            quote_identifier(table),
            quote_identifier(column),
            literal
        );
        client.execute(&sql)?;
        client.close()
    }

    /// Rows are artefacts, and the simple flow holds no transaction to
    /// claim one in.
    fn claims(&self) -> Option<&dyn ResourceClaim> {
        Some(&NoNativeClaim)
    }
}

impl PostgresTransport {
    /// Both ends on this machine: an ephemeral local port, a login by
    /// trust, the loopback timeout.
    #[must_use]
    pub fn loopback() -> Self {
        Self::new("127.0.0.1:0", LOOPBACK_USER, LOOPBACK_DATABASE)
            .timing_out_after(LOOPBACK_TIMEOUT)
    }
}

/// A bound listener waiting for its one client: logged in, one INSERT
/// taken as the Stream, its Terminate read.
struct Listening {
    transport: PostgresTransport,
    listener: TcpListener,
    address: String,
}

impl FarEnd for Listening {
    fn address(&self) -> &str {
        &self.address
    }

    fn take_one(self: Box<Self>) -> Result<Arrived> {
        let mut session = self.transport.accept_one(&self.listener)?;
        let arrived = session
            .next_insert()?
            .ok_or_else(|| protocol_error("the client closed without inserting"))?;
        // Read the Terminate that follows, so the goodbye is taken rather
        // than written into a closed socket.
        session.next_insert()?;
        Ok(arrived)
    }
}

impl Loopback for PostgresTransport {
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        let (listener, address) = self.bind()?;
        Ok(Box::new(Listening {
            transport: self.clone(),
            listener,
            address,
        }))
    }

    /// INSERT the payload as one column of one row — text as text, anything
    /// else in the bytea hex form — from a fresh near end logging in to
    /// `address` as this transport does.
    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        let near = Self {
            server: address.to_string(),
            ..self.clone()
        };
        near.send(LOOPBACK_TARGET, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn a_receive_runs_the_query_and_each_row_is_a_stream() {
        let far_end =
            PostgresTransport::new("127.0.0.1:0", "xmip", "orders").timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let receiver = std::thread::spawn(move || {
            PostgresTransport::new(address, "xmip", "orders")
                .querying("SELECT id, kind, payload FROM inbox ORDER BY id")
                .timing_out_after(secs(2))
                .receive()
        });
        let mut session = far_end
            .accept_one(&listener)
            .expect("accepting")
            .with_table(
                &["id", "kind", "payload"],
                &[
                    &[Some("41"), Some("order"), Some("ISA*00*")],
                    &[Some("42"), None, None],
                    &[None, Some("x"), Some("named by index")],
                ],
            );
        assert_eq!(session.user(), "xmip");
        assert_eq!(session.database(), "orders");
        let event = session.next_event().expect("query").expect("one");
        assert_eq!(
            event,
            Event::Selected("SELECT id, kind, payload FROM inbox ORDER BY id".into())
        );
        assert!(session.next_event().expect("terminated").is_none());
        let arrived = receiver.join().expect("thread").expect("receiving");
        assert_eq!(arrived.len(), 3);
        assert_eq!(arrived[0].bytes, b"ISA*00*");
        assert!(arrived[0].origin_uri.ends_with("/orders?row=41"));
        assert!(arrived[1].bytes.is_empty(), "NULL is an empty Stream");
        assert!(arrived[1].origin_uri.ends_with("?row=42"));
        assert!(arrived[2].origin_uri.ends_with("?row=2"));
    }

    #[test]
    fn a_send_inserts_the_stream_as_one_column_and_the_login_is_checked() {
        let far_end = PostgresTransport::new("127.0.0.1:0", "xmip", "orders")
            .with_password("secret")
            .timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let sender = std::thread::spawn(move || {
            let near = PostgresTransport::new(address.clone(), "xmip", "orders")
                .with_password("secret")
                .timing_out_after(secs(2));
            near.send(
                &format!("postgresql://{address}/orders/inbox/payload"),
                b"it's here",
            )?;
            near.send("outbox/body", b"")?;
            near.send(&format!("{address}/orders/inbox/payload"), &[0xff, 0xfe])?;
            let bad_target = near.send("postgres://host/only-one", b"x");
            let refused = PostgresTransport::new(address, "xmip", "orders")
                .with_password("wrong")
                .timing_out_after(secs(2))
                .send("inbox/payload", b"x");
            Ok::<_, TransportError>((bad_target, refused))
        });
        let mut session = far_end.accept_one(&listener).expect("accepting");
        let first = session.next_insert().expect("first").expect("one");
        assert_eq!(first.bytes, b"it's here");
        assert!(first.origin_uri.ends_with("/orders/inbox/payload"));
        assert!(session.next_insert().expect("closed").is_none());
        let mut session = far_end.accept_one(&listener).expect("second");
        let second = session.next_insert().expect("second").expect("one");
        assert!(second.bytes.is_empty());
        assert!(second.origin_uri.ends_with("/orders/outbox/body"));
        let mut session = far_end.accept_one(&listener).expect("third");
        let binary = session.next_insert().expect("third").expect("one");
        assert_eq!(
            binary.bytes,
            [0xff, 0xfe],
            "not text, so the bytea hex form"
        );
        let error = far_end.accept_one(&listener).err().expect("wrong password");
        assert!(error.message.contains("password authentication failed"));
        let (bad_target, refused) = sender.join().expect("thread").expect("sending");
        assert!(!bad_target.expect_err("not a column").retryable);
        let refused = refused.expect_err("wrong password");
        assert!(!refused.retryable);
        assert!(refused.message.contains("28P01"));
        assert!(far_end.claims().is_some(), "rows are artefacts");
        assert_eq!(far_end.name(), "postgresql");
    }

    #[test]
    fn a_server_asking_for_scram_or_speaking_nonsense_is_refused() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address").to_string();
        std::thread::spawn(move || {
            for answer in [
                &backend::encode_backend(&backend::Backend::Authentication(wire::AUTH_SASL))[..],
                &backend::encode_backend(&backend::Backend::Authentication(wire::AUTH_CLEARTEXT))[..],
                b"HTTP/1.1 400 Bad Request\r\n\r\n",
            ] {
                let (mut stream, _) = listener.accept().expect("accept");
                let mut sink = [0u8; 1024];
                let _ = std::io::Read::read(&mut stream, &mut sink);
                std::io::Write::write_all(&mut stream, answer).expect("write");
                let _ = std::io::Read::read(&mut stream, &mut sink);
            }
        });
        let near = PostgresTransport::new(address, "xmip", "orders").timing_out_after(secs(2));
        let error = near.connect().err().expect("SCRAM");
        assert!(!error.retryable);
        assert!(error.message.contains("SCRAM"));
        let error = near.connect().err().expect("no password configured");
        assert!(error.message.contains("none is configured"));
        assert!(!near.connect().err().expect("not the protocol").retryable);
    }

    #[test]
    fn the_loopback_inserts_text_and_bytes_through_its_own_session() {
        let pair = PostgresTransport::loopback();
        let arrived = pair.round(b"it's here").expect("round");
        assert_eq!(arrived.bytes, b"it's here");
        assert!(arrived.origin_uri.starts_with("postgresql://127.0.0.1:"));
        assert!(arrived.origin_uri.ends_with("/probe/probe/payload"));
        let binary = pair.round(&[0xff, 0xfe]).expect("the bytea hex form");
        assert_eq!(binary.bytes, [0xff, 0xfe]);
        assert_eq!(pair.name(), "postgresql");
        assert_eq!(pair.ceiling(), None);
    }

    /// The Playground's edge payloads, written here so the crate does not
    /// depend on it.
    fn edge_payloads() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("empty", Vec::new()),
            ("one byte", vec![0x2a]),
            ("every byte", (0..=255).collect()),
            ("nul run", vec![0; 512]),
            ("high bytes", vec![0xff; 512]),
            ("crlf storm", b"\r\n".repeat(400)),
        ]
    }

    #[test]
    fn the_loopback_returns_the_edge_payloads_whole() {
        let pair = PostgresTransport::loopback();
        for (name, payload) in edge_payloads() {
            assert!(pair.refuses(&payload).is_none(), "{name}");
            let arrived = pair.round(&payload).expect(name);
            assert_eq!(arrived.bytes, payload, "{name}");
        }
    }
}
