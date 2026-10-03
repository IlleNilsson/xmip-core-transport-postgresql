#![forbid(unsafe_code)]

//! Streams that arrive as rows. One row is one Stream: the last column of
//! a configured query is what Xmip carries, the first column is where it
//! came from.
//!
//! `PostgreSQL` is the database the estate's Parties already have, and a
//! table in it is the oldest integration surface there is: a producer
//! inserts, an integrator polls. A Receive Location runs its query — `SELECT
//! id, payload FROM inbox ORDER BY id` unless told otherwise — and hands
//! each row up whole; a Send Location inserts the Stream as one column of
//! one row. What the column holds is the Location's to declare, never the
//! bytes' (ADR-0038): `column = "binary"`, the default, inserts every
//! Stream in the bytea hex form and reads a value back from it
//! (`bytea.rs`); `column = "text"` decodes the Stream strictly in its
//! `encoding` — `utf-8` unless another Unicode form is named — inserts it
//! as a string literal, and encodes a value read back to that form. A
//! Stream that is not its declared form is refused, never repaired. What
//! is spoken is the frontend/backend protocol, version 3.0, in
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
//! **A row is consumed by the `accept` statement, after its cycle.** The
//! query only reads. Where the Location declares `accept` — `DELETE FROM
//! inbox WHERE id = $1` — it runs once a row's cycle accepted or refused
//! it, the row's name bound in place of `$1` (`transport::sql::accept`),
//! written as a string literal by `quote_literal`: a table has no
//! place for a refused row, the runtime audited the refusal, and from
//! Message creation on the Stream is kept in Xmip (ADR-0013). A row whose
//! cycle failed is left, and the next receive reads it again; so is a row
//! whose name is NULL, which no statement can name. Where `accept` is left
//! out a row's verdict tells the database nothing: every row is read again
//! unless the query keeps it from that, and a query that consumes as it
//! reads — a `DELETE … RETURNING` — consumes before the receive cycle has
//! run, so acceptance is at-most-once under such a query.
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
use std::sync::Arc;
use std::time::Duration;

pub use client::{Client, QueryResult, quote_literal};
pub use session::{Answer, Event, Session};
use transport::claim::{NoNativeClaim, ResourceClaim};
use transport::error::{Result, protocol_error};
use transport::listening::{Accepting, Listening};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::socket;
use transport::sql::{COLUMN, Column, ENCODING, accept};
use transport::{Arrived, Configured, Directions, Pool, Taken, Transport};

use session::DIALECT;
use xcore::settings::{Applies, Fixed, Kind, Presence, Read, Setting, Settings};

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
    /// The statement run on a row's verdict, its name bound in.
    accept: Option<String>,
    column: Column,
    timeout: Option<Duration>,
    /// The connections a send inserts on and a receive queries on, logged
    /// in once per server and database and kept.
    connections: Pool<Client>,
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
            accept: None,
            column: Column::Binary,
            timeout: None,
            connections: Pool::new(),
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

    /// The statement run once a row's cycle accepted or refused it, the
    /// row's name in place of `$1` (`transport::sql::accept`).
    #[must_use]
    pub fn accepting(mut self, statement: impl Into<String>) -> Self {
        self.accept = Some(statement.into());
        self
    }

    /// What the payload column holds: bytes unless declared otherwise.
    #[must_use]
    pub const fn holding(mut self, column: Column) -> Self {
        self.column = column;
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
            .map(|session| session.holding(self.column))
    }
}

impl Transport for PostgresTransport {
    fn name(&self) -> &'static str {
        "postgresql"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    fn arrivals(&self) -> transport::Arrivals {
        transport::Arrivals::Ordered("a poll reads again what is not yet told")
    }

    /// Run the query on the connection kept for the server and database,
    /// logged in on the first receive; each row is a Stream, whole. Its
    /// verdict runs the `accept` statement where one is declared — on
    /// `Accepted` and `Refused`, never on `Failed` — and tells the database
    /// nothing where none is: whether a row is read again is then the
    /// query's (a query that consumes as it reads makes acceptance
    /// at-most-once).
    fn receive(&self) -> Result<Vec<Arrived>> {
        let result = self.connections.exchange(
            &format!("{}/{}", self.server, self.database),
            || self.connect(),
            |client| client.query(&self.query),
        )?;
        let shared = Arc::new(self.clone());
        accept::arrivals(
            result.rows,
            |name| format!("postgresql://{}/{}?row={name}", self.server, self.database),
            Clone::clone,
            |value| self.column.bytes(&value, bytea::from_hex_literal),
            |name| {
                let transport = Arc::clone(&shared);
                DIALECT.accepting(self.accept.as_deref(), name, quote_literal, move |sql| {
                    transport.connections.exchange(
                        &format!("{}/{}", transport.server, transport.database),
                        || transport.connect(),
                        |client| client.execute(sql).map(|_| ()),
                    )
                })
            },
        )
    }

    /// Insert the bytes as one column of one row: in the bytea hex form,
    /// or as text where the column is declared to hold it — on the
    /// connection kept for the server and database, logged in on the first
    /// send to them.
    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        let to = DIALECT.destination(target, &self.server, &self.database)?;
        let literal = self.column.literal(bytes, quote_literal, |bytes| {
            quote_literal(&bytea::hex_literal(bytes))
        })?;
        let insert = DIALECT.insert(to.table, to.column, &literal);
        self.connections.exchange(
            &format!("{}/{}", to.server, to.catalog),
            || self.connect_to(to.server, to.catalog),
            |client| client.execute(&insert).map(|_| ()),
        )
    }

    /// Rows are artefacts, and the simple flow holds no transaction to
    /// claim one in.
    fn claims(&self) -> Option<&dyn ResourceClaim> {
        Some(&NoNativeClaim)
    }
}

impl Configured for PostgresTransport {
    /// The address is the server's host and port: where a Location connects.
    const SETTINGS: &'static Settings = &Settings {
        technology: env!("CARGO_PKG_NAME"),
        settings: &[
            Setting {
                name: "user",
                kind: Kind::Text,
                presence: Presence::Required,
                meaning: "The user a Location logs in as.",
                applies: Applies::Both,
            },
            Setting {
                name: "database",
                kind: Kind::Text,
                presence: Presence::Required,
                meaning: "The database a Location logs in to and reads or inserts into.",
                applies: Applies::Both,
            },
            Setting {
                name: "query",
                kind: Kind::Text,
                presence: Presence::Default(Fixed::Text(DEFAULT_QUERY)),
                meaning: "The query a receive runs: the first column names the row, the last \
                          is the Stream.",
                applies: Applies::Receive,
            },
            accept::ACCEPT,
            COLUMN,
            ENCODING,
            Setting {
                name: "timeout",
                kind: Kind::Duration,
                presence: Presence::Optional,
                meaning: "How long a server that stops mid-message is waited on; unbounded \
                          when left out.",
                applies: Applies::Both,
            },
        ],
    };

    /// The password comes through the Location's credentials, never a
    /// setting.
    fn configured(address: &str, settings: &Read) -> Result<Self> {
        let mut transport = Self::new(address, settings.text("user"), settings.text("database"));
        if let Some(query) = settings.optional_text("query") {
            transport = transport.querying(query);
        }
        if let Some(statement) = settings.optional_text(accept::ACCEPT.name) {
            transport = transport.accepting(statement);
        }
        if let Some(timeout) = settings.optional_duration("timeout") {
            transport = transport.timing_out_after(timeout);
        }
        Ok(transport.holding(Column::configured(settings)?))
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

impl Accepting for PostgresTransport {
    fn take_one(self, listener: &TcpListener) -> Result<Taken> {
        // The client keeps its connection for the next insert.
        self.accept_one(listener)?
            .next_insert()?
            .ok_or_else(|| protocol_error("the client closed without inserting"))
    }
}

impl Loopback for PostgresTransport {
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        Ok(Box::new(Listening::new(self.clone(), self.bind()?)))
    }

    /// INSERT the payload as one column of one row, as the column is
    /// declared to hold it, from a fresh near end logging in to
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
    use codec::unicode::Form;
    use transport::error::TransportError;
    use transport::payload::edge_payloads;

    /// The bytes 0xff 0xfe as a bytea column answers them.
    const HEX_FFFE: &str = "\\xfffe";

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn postgresql_declares_its_settings_and_reads_through_them() {
        use xcore::settings::Given;
        assert_eq!(PostgresTransport::SETTINGS.problems(), Vec::<String>::new());
        let text = |name: &str, value: &str| (name.to_string(), Given::Text(value.to_string()));
        let given = [
            text("user", "xmip"),
            text("database", "orders"),
            text("timeout", "2s"),
        ];
        let built = PostgresTransport::open("db:5432", Applies::Receive, &given).expect("built");
        assert_eq!(built.server, "db:5432");
        assert_eq!(built.user, "xmip");
        assert_eq!(built.database, "orders");
        assert_eq!(built.query, DEFAULT_QUERY);
        assert_eq!(built.accept, None, "nothing runs unless declared");
        assert_eq!(built.password, None);
        assert_eq!(built.timeout, Some(secs(2)));
        assert_eq!(built.column, Column::Binary, "bytes unless declared");
        let texts = [
            text("user", "xmip"),
            text("database", "orders"),
            text("column", "text"),
            text("encoding", "utf-16le"),
        ];
        let built = PostgresTransport::open("db:5432", Applies::Send, &texts).expect("text");
        assert_eq!(built.column, Column::Text(Form::Utf16Le));
        let accepting = [
            text("user", "xmip"),
            text("database", "orders"),
            text("accept", "DELETE FROM inbox WHERE id = $1"),
        ];
        let built =
            PostgresTransport::open("db:5432", Applies::Receive, &accepting).expect("accept");
        assert_eq!(
            built.accept.as_deref(),
            Some("DELETE FROM inbox WHERE id = $1")
        );
        let Err(refused) = PostgresTransport::open("db:5432", Applies::Send, &given[1..]) else {
            panic!("user is required");
        };
        assert!(refused.message.contains("\"user\""), "{}", refused.message);
    }

    /// The first of `arrived` read and refused, the rest taken.
    fn verdicts(arrived: Vec<Arrived>) -> Result<Vec<Taken>> {
        let mut taken = Vec::new();
        for (index, one) in arrived.into_iter().enumerate() {
            assert!(one.defers());
            if index > 0 {
                taken.push(one.taken()?);
                continue;
            }
            let (origin, mut body, acknowledgement) = one.into_parts();
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut body, &mut bytes).expect("reading");
            acknowledgement.acknowledge(transport::Verdict::Failed)?;
            taken.push(Taken::new(origin, bytes));
        }
        Ok(taken)
    }

    #[test]
    fn a_receive_runs_the_query_and_each_row_is_a_stream() {
        let far_end =
            PostgresTransport::new("127.0.0.1:0", "xmip", "orders").timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let receiver = std::thread::spawn(move || {
            let near = PostgresTransport::new(address, "xmip", "orders")
                .querying("SELECT id, kind, payload FROM inbox ORDER BY id")
                .holding(Column::Text(Form::Utf8))
                .timing_out_after(secs(2));
            verdicts(near.receive()?)
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
        assert!(
            session.next_event().expect("terminated").is_none(),
            "a verdict, refused or accepted, says nothing to the database"
        );
        let arrived = receiver.join().expect("thread").expect("receiving");
        assert_eq!(arrived.len(), 3);
        assert_eq!(arrived[0].bytes, b"ISA*00*");
        assert!(arrived[0].origin_uri.ends_with("/orders?row=41"));
        assert!(arrived[1].bytes.is_empty(), "NULL is an empty Stream");
        assert!(arrived[1].origin_uri.ends_with("?row=42"));
        assert!(arrived[2].origin_uri.ends_with("?row=2"));
    }

    #[test]
    fn the_accept_statement_consumes_an_accepted_and_a_refused_row_after_the_cycle() {
        let far_end =
            PostgresTransport::new("127.0.0.1:0", "xmip", "orders").timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let receiver = std::thread::spawn(move || {
            let near = PostgresTransport::new(address, "xmip", "orders")
                .accepting("DELETE FROM inbox WHERE id = $1")
                .holding(Column::Text(Form::Utf8))
                .timing_out_after(secs(2));
            let mut arrived = near.receive()?;
            assert_eq!(arrived.len(), 4);
            arrived.remove(0).taken()?;
            arrived
                .remove(0)
                .refused(transport::Refusal::Unacceptable)?;
            arrived.remove(0).failed()?;
            arrived.remove(0).taken()?;
            Ok::<_, TransportError>(())
        });
        let mut session = far_end
            .accept_one(&listener)
            .expect("accepting")
            .with_table(
                &["id", "payload"],
                &[
                    &[Some("41"), Some("accepted")],
                    &[Some("it's"), Some("refused")],
                    &[Some("43"), Some("failed")],
                    &[None, Some("unnamed")],
                ],
            );
        let mut events = Vec::new();
        while let Some(event) = session.next_event().expect("serving") {
            events.push(event);
        }
        receiver.join().expect("thread").expect("receiving");
        assert_eq!(
            events,
            [
                Event::Selected(DEFAULT_QUERY.into()),
                Event::Executed("DELETE FROM inbox WHERE id = '41'".into()),
                Event::Executed("DELETE FROM inbox WHERE id = 'it''s'".into()),
            ],
            "the failed row and the unnamed one are left"
        );
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
        // One server and database, so one login for all three inserts.
        let mut session = far_end.accept_one(&listener).expect("accepting");
        let first = session.next_insert().expect("first").expect("one");
        assert_eq!(first.bytes, b"it's here");
        assert!(first.origin_uri.ends_with("/orders/inbox/payload"));
        let second = session.next_insert().expect("second").expect("one");
        assert!(second.bytes.is_empty());
        assert!(second.origin_uri.ends_with("/orders/outbox/body"));
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
    fn a_thousand_inserts_log_in_once_and_a_connection_the_server_closed_is_replaced() {
        const SENDS: usize = 1000;
        let far_end = PostgresTransport::new("127.0.0.1:0", "xmip", "orders")
            .with_password("secret")
            .timing_out_after(secs(5));
        let (listener, address) = far_end.bind().expect("binding");
        let near = PostgresTransport::new(address, "xmip", "orders")
            .with_password("secret")
            .timing_out_after(secs(5));
        let sending = near.clone();
        let sender = std::thread::spawn(move || {
            let began = std::time::Instant::now();
            for n in 0..SENDS {
                sending.send("inbox/payload", n.to_string().as_bytes())?;
            }
            let took = began.elapsed();
            // Generous for a debug build under load: a millisecond an insert.
            assert!(took < Duration::from_millis(SENDS as u64), "{took:?}");
            sending.send("inbox/payload", b"after the close")
        });
        // One startup and password for every insert: one session accepted.
        let mut session = far_end.accept_one(&listener).expect("accepting");
        for n in 0..SENDS {
            let inserted = session.next_insert().expect("insert").expect("one");
            assert_eq!(inserted.bytes, n.to_string().as_bytes());
        }
        drop(session);
        let mut again = far_end.accept_one(&listener).expect("a new login");
        let last = again.next_insert().expect("insert").expect("one");
        assert_eq!(last.bytes, b"after the close");
        sender.join().expect("thread").expect("sending");
        assert_eq!(near.connections.opened(), 2);
    }

    #[test]
    fn a_thousand_receives_log_in_once_and_a_connection_the_server_closed_is_replaced() {
        const RECEIVES: usize = 1000;
        let far_end =
            PostgresTransport::new("127.0.0.1:0", "xmip", "orders").timing_out_after(secs(5));
        let (listener, address) = far_end.bind().expect("binding");
        let near = PostgresTransport::new(address, "xmip", "orders").timing_out_after(secs(5));
        let receiving = near.clone();
        let receiver = std::thread::spawn(move || {
            let began = std::time::Instant::now();
            for _ in 0..RECEIVES {
                assert_eq!(receiving.receive()?.len(), 1);
            }
            let took = began.elapsed();
            // Generous for a debug build under load: a millisecond a query.
            assert!(took < Duration::from_millis(RECEIVES as u64), "{took:?}");
            receiving.receive()
        });
        let accept = || {
            far_end
                .accept_one(&listener)
                .expect("a login")
                .with_table(&["id", "payload"], &[&[Some("1"), None]])
        };
        // One startup for every query: one session accepted.
        let mut session = accept();
        for _ in 0..RECEIVES {
            let event = session.next_event().expect("query");
            assert!(matches!(event, Some(Event::Selected(_))), "{event:?}");
        }
        drop(session);
        let mut again = accept();
        assert!(matches!(again.next_event(), Ok(Some(Event::Selected(_)))));
        assert_eq!(receiver.join().expect("thread").expect("after").len(), 1);
        assert_eq!(near.connections.opened(), 2);
    }

    #[test]
    fn a_binary_column_reads_the_hex_form_and_refuses_what_is_not() {
        let far_end =
            PostgresTransport::new("127.0.0.1:0", "xmip", "orders").timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let receiver = std::thread::spawn(move || {
            // Two transports, so two sessions: each keeps its own.
            let near = || {
                PostgresTransport::new(address.clone(), "xmip", "orders").timing_out_after(secs(2))
            };
            let bytes = near().receive().and_then(verdicts);
            (bytes, near().receive().and_then(verdicts))
        });
        let rows: [&[Option<&str>]; 1] = [&[Some("1"), Some(HEX_FFFE)]];
        let mut session = far_end
            .accept_one(&listener)
            .expect("first")
            .with_table(&["id", "payload"], &rows);
        while session.next_event().expect("event").is_some() {}
        let text: [&[Option<&str>]; 1] = [&[Some("2"), Some("ISA*00*")]];
        let mut session = far_end
            .accept_one(&listener)
            .expect("second")
            .with_table(&["id", "payload"], &text);
        while session.next_event().expect("event").is_some() {}
        let (bytes, text) = receiver.join().expect("thread");
        assert_eq!(bytes.expect("the hex form")[0].bytes, [0xff, 0xfe]);
        let refused = text.expect_err("text in a binary column");
        assert!(
            refused.message.contains("column = \"text\""),
            "{}",
            refused.message
        );
    }

    #[test]
    fn a_text_column_refuses_a_stream_that_is_not_its_encoding() {
        let near = PostgresTransport::new("127.0.0.1:1", "xmip", "orders")
            .holding(Column::Text(Form::Utf8));
        let refused = near
            .send("inbox/payload", &[0xff, 0xfe])
            .expect_err("not UTF-8");
        assert!(!refused.retryable);
        assert!(
            refused.message.contains("utf-8 text"),
            "{}",
            refused.message
        );
    }

    #[test]
    fn a_server_asking_for_scram_or_speaking_nonsense_is_refused() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address").to_string();
        std::thread::spawn(move || {
            let asking =
                |method| backend::encode_backend(&backend::Backend::Authentication(method));
            for answer in [
                &asking(wire::AUTH_SASL)[..],
                &asking(wire::AUTH_CLEARTEXT)[..],
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
