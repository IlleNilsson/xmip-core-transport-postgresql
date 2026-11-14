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
//! (`PostgreSQL`'s, `xmip-core-library-sql`); `column = "text"` decodes
//! the Stream strictly in its `encoding` — `utf-8` unless another Unicode
//! form is named — inserts it as a string literal, and encodes a value
//! read back to that form. A Stream that is not its declared form is
//! refused, never repaired.
//!
//! **The transport is every SQL technology's**, `transport::sql`'s
//! `SqlTransport` over this crate's [`PostgreSql`] wire (2026-11-13): the
//! query and its rows, the `accept` statement after a row's cycle — the
//! row's name in place of `$1`, written as `PostgreSQL`'s string literal —
//! the INSERT a send writes, the connections kept per server and database.
//!
//! **The protocol is `xmip-core-library-postgresql`'s**: the
//! frontend/backend protocol, version 3.0, in its simple query flow, on
//! port 5432 — startup, trust or a cleartext password, `Query`, rows as
//! text, `Terminate` — and the far end the tests and the Essentials serve.
//! MD5 and SCRAM are not implemented and a server that asks for them is
//! told so; TLS is the transport capability's, per ADR-0033.
//!
//! The origin URI carries what the row knew:
//! `postgresql://server/orders?row=41`. A send target is
//! `postgresql://host:5432/<database>/<table>/<column>`,
//! `host:5432/<database>/<table>/<column>`, or `<table>/<column>` on the
//! configured server and database.

use std::net::TcpListener;
use std::time::Duration;

use postgresql::{Client, Insert, Session};
use sql::{Dialect, Literal, POSTGRESQL};
use transport::error::{Result, protocol_error};
use transport::pool::alive;
use transport::socket;
use transport::sql::accept::ACCEPT;
use transport::sql::{
    COLUMN, DATABASE, ENCODING, Probe, QUERY, Rows, SqlTransport, TIMEOUT, USER, Wire,
};
use transport::{Login, Taken};
use xcore::settings::Settings;

/// A Location over a `PostgreSQL` server.
pub type PostgresTransport = SqlTransport<PostgreSql>;

/// `PostgreSQL`'s wire: `xmip-core-library-postgresql`'s client, logging in
/// by trust or a cleartext password.
#[derive(Clone, Copy, Debug, Default)]
pub struct PostgreSql;

impl Wire for PostgreSql {
    type Client = Client;

    const NAME: &'static str = "postgresql";
    const SCHEMES: &'static [&'static str] = &["postgresql", "postgres"];
    /// The address is the server's host and port: where a Location
    /// connects.
    const SETTINGS: &'static Settings = &Settings {
        technology: env!("CARGO_PKG_NAME"),
        settings: &[USER, DATABASE, QUERY, ACCEPT, COLUMN, ENCODING, TIMEOUT],
    };
    /// One user logged in by trust.
    const PROBE: Probe = Probe {
        database: "probe",
        user: "probe",
        password: "",
        target: "probe/payload",
    };

    fn dialect() -> &'static Dialect {
        &POSTGRESQL
    }

    /// The password given where the server asks for one in the clear; none
    /// where the login carries none.
    fn connect(
        &self,
        server: &str,
        database: &str,
        login: &Login,
        timeout: Option<Duration>,
    ) -> Result<Client> {
        let password = (!login.password.is_empty()).then_some(login.password.as_str());
        Ok(Client::connect(
            server,
            &login.user,
            database,
            password,
            timeout,
        )?)
    }

    /// While the server has not closed the connection. Each statement runs
    /// in the simple query flow and ends at `ReadyForQuery`, so nothing of
    /// one is left for the next.
    fn usable(client: &mut Client) -> bool {
        alive(client.socket())
    }

    fn query(client: &mut Client, sql: &str) -> Result<Rows<String>> {
        Ok(client.query(sql)?.rows)
    }

    fn execute(client: &mut Client, sql: &str) -> Result<()> {
        client.execute(sql)?;
        Ok(())
    }

    /// The client keeps its connection for the next insert.
    fn take_one(transport: &PostgresTransport, listener: &TcpListener) -> Result<Taken> {
        let mut session = accept_one(transport, listener)?;
        let insert = session
            .next_insert()?
            .ok_or_else(|| protocol_error("the client closed without inserting"))?;
        taken(transport, &session, insert)
    }
}

/// Accept one client on a listener `transport` bound, demanding its
/// password in the clear where it has one, by trust where it has none.
///
/// # Errors
/// Where the connection could not be accepted or the login failed.
pub fn accept_one(transport: &PostgresTransport, listener: &TcpListener) -> Result<Session> {
    let (stream, _) = socket::accept_tcp(listener, transport.timeout())?;
    let password = &transport.login().password;
    Ok(Session::accept(
        stream,
        (!password.is_empty()).then_some(password.as_str()),
    )?)
}

/// The Stream `insert` carries, read from its literal as `transport`'s
/// column holds it, its origin where `session` received it.
///
/// # Errors
/// A literal that is not what the column is declared to hold.
pub fn taken(transport: &PostgresTransport, session: &Session, insert: Insert) -> Result<Taken> {
    let bytes = match insert.literal {
        Literal::Text(value) => transport.column().bytes(&value, &POSTGRESQL)?,
        Literal::Bytes(bytes) => bytes,
    };
    Ok(PostgresTransport::inserted(
        session.peer(),
        session.database(),
        &insert.table,
        &insert.column,
        bytes,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::unicode::Form;
    use postgresql::Event;
    use postgresql::backend::{Backend, encode_backend};
    use postgresql::wire::{AUTH_CLEARTEXT, AUTH_SASL};
    use std::assert_matches;
    use transport::error::TransportError;
    use transport::payload::edge_payloads;
    use transport::sql::{Column, DEFAULT_QUERY};
    use transport::{Arrived, Configured, Loopback, Transport};
    use xcore::settings::Applies;

    /// The bytes 0xff 0xfe as a bytea column answers them.
    const HEX_FFFE: &str = "\\xfffe";

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    /// The next Stream the client inserts on `session`, as `far_end`'s
    /// column reads it.
    fn next_taken(far_end: &PostgresTransport, session: &mut Session) -> Taken {
        let insert = session.next_insert().expect("insert").expect("one");
        taken(far_end, session, insert).expect("the column's form")
    }

    #[test]
    fn postgresql_declares_its_settings_and_reads_through_them() {
        use xcore::settings::Given;
        assert_eq!(PostgresTransport::SETTINGS.problems(), Vec::<String>::new());
        let text = |name: &str, value: &str| (name.to_string(), Given::Text(value.to_string()));
        let given = [text("user", "xmip"), text("database", "orders")];
        let built = PostgresTransport::open("db:5432", Applies::Receive, &given).expect("built");
        assert_eq!((built.server(), built.database()), ("db:5432", "orders"));
        assert_eq!(built.login().user, "xmip");
        assert!(built.login().password.is_empty(), "the secret's, by trust");
        assert_eq!(built.query(), DEFAULT_QUERY);
        assert_eq!(built.name(), "postgresql");
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
            PostgresTransport::new("127.0.0.1:0", "orders", "xmip").timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let receiver = std::thread::spawn(move || {
            let near = PostgresTransport::new(address, "orders", "xmip")
                .with_query("SELECT id, kind, payload FROM inbox ORDER BY id")
                .holding(Column::Text(Form::Utf8))
                .timing_out_after(secs(2));
            verdicts(near.receive()?)
        });
        let mut session = accept_one(&far_end, &listener)
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
    fn accept_consumes_an_accepted_row_and_a_refused_one_is_left_unreceived() {
        let far_end =
            PostgresTransport::new("127.0.0.1:0", "orders", "xmip").timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let receiver = std::thread::spawn(move || {
            let near = PostgresTransport::new(address, "orders", "xmip")
                .with_accept("DELETE FROM inbox WHERE id = $1")
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
            let again: Vec<_> = near.receive()?.into_iter().map(|a| a.origin_uri).collect();
            assert_eq!(
                again.len(),
                3,
                "the refused row is not received again: {again:?}"
            );
            assert!(
                again.iter().all(|row| !row.ends_with("?row=it's")),
                "{again:?}"
            );
            Ok::<_, TransportError>(())
        });
        let mut session = accept_one(&far_end, &listener)
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
                Event::Selected(DEFAULT_QUERY.into()),
            ],
            "the refused, the failed and the unnamed row are left"
        );
    }

    #[test]
    fn a_send_inserts_the_stream_as_one_column_and_the_login_is_checked() {
        let far_end = PostgresTransport::new("127.0.0.1:0", "orders", "xmip")
            .with_password("secret")
            .timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let sender = std::thread::spawn(move || {
            let near = PostgresTransport::new(address.clone(), "orders", "xmip")
                .with_password("secret")
                .timing_out_after(secs(2));
            near.send(
                &format!("postgresql://{address}/orders/inbox/payload"),
                b"it's here",
            )?;
            near.send("outbox/body", b"")?;
            near.send(&format!("{address}/orders/inbox/payload"), &[0xff, 0xfe])?;
            let bad_target = near.send("postgres://host/only-one", b"x");
            let refused = PostgresTransport::new(address, "orders", "xmip")
                .with_password("wrong")
                .timing_out_after(secs(2))
                .send("inbox/payload", b"x");
            Ok::<_, TransportError>((bad_target, refused))
        });
        // One server and database, so one login for all three inserts.
        let mut session = accept_one(&far_end, &listener).expect("accepting");
        let first = next_taken(&far_end, &mut session);
        assert_eq!(first.bytes, b"it's here");
        assert!(first.origin_uri.ends_with("/orders/inbox/payload"));
        let second = next_taken(&far_end, &mut session);
        assert_eq!(second.bytes, [] as [u8; 0]);
        assert!(second.origin_uri.ends_with("/orders/outbox/body"));
        let binary = next_taken(&far_end, &mut session);
        assert_eq!(
            binary.bytes,
            [0xff, 0xfe],
            "not text, so the bytea hex form"
        );
        let error = accept_one(&far_end, &listener)
            .err()
            .expect("wrong password");
        assert!(error.message.contains("password authentication failed"));
        let (bad_target, refused) = sender.join().expect("thread").expect("sending");
        assert!(!bad_target.expect_err("not a column").retryable);
        let refused = refused.expect_err("wrong password");
        assert!(!refused.retryable);
        assert!(refused.message.contains("28P01"));
        assert!(far_end.claims().is_some(), "rows are artifacts");
    }

    #[test]
    fn a_thousand_inserts_log_in_once_and_a_connection_the_server_closed_is_replaced() {
        const SENDS: usize = 1000;
        let far_end = PostgresTransport::new("127.0.0.1:0", "orders", "xmip")
            .with_password("secret")
            .timing_out_after(secs(5));
        let (listener, address) = far_end.bind().expect("binding");
        let near = PostgresTransport::new(address, "orders", "xmip")
            .with_password("secret")
            .timing_out_after(secs(5));
        let sending = near.clone();
        let sender = std::thread::spawn(move || {
            for n in 0..SENDS {
                sending.send("inbox/payload", n.to_string().as_bytes())?;
            }
            sending.send("inbox/payload", b"after the close")
        });
        // One startup and password for every insert: one session accepted.
        let mut session = accept_one(&far_end, &listener).expect("accepting");
        for n in 0..SENDS {
            let inserted = next_taken(&far_end, &mut session);
            assert_eq!(inserted.bytes, n.to_string().as_bytes());
        }
        drop(session);
        let mut again = accept_one(&far_end, &listener).expect("a new login");
        let last = next_taken(&far_end, &mut again);
        assert_eq!(last.bytes, b"after the close");
        sender.join().expect("thread").expect("sending");
        assert_eq!(near.opened(), 2);
    }

    #[test]
    fn a_thousand_receives_log_in_once_and_a_connection_the_server_closed_is_replaced() {
        const RECEIVES: usize = 1000;
        let far_end =
            PostgresTransport::new("127.0.0.1:0", "orders", "xmip").timing_out_after(secs(5));
        let (listener, address) = far_end.bind().expect("binding");
        let near = PostgresTransport::new(address, "orders", "xmip").timing_out_after(secs(5));
        let receiving = near.clone();
        let receiver = std::thread::spawn(move || {
            for _ in 0..RECEIVES {
                assert_eq!(receiving.receive()?.len(), 1);
            }
            receiving.receive()
        });
        let accept = || {
            accept_one(&far_end, &listener)
                .expect("a login")
                .with_table(&["id", "payload"], &[&[Some("1"), None]])
        };
        // One startup for every query: one session accepted.
        let mut session = accept();
        for _ in 0..RECEIVES {
            let event = session.next_event().expect("query");
            assert_matches!(event, Some(Event::Selected(_)), "{event:?}");
        }
        drop(session);
        let mut again = accept();
        assert_matches!(again.next_event(), Ok(Some(Event::Selected(_))));
        assert_eq!(receiver.join().expect("thread").expect("after").len(), 1);
        assert_eq!(near.opened(), 2);
    }

    #[test]
    fn a_binary_column_reads_the_hex_form_and_refuses_what_is_not() {
        let far_end =
            PostgresTransport::new("127.0.0.1:0", "orders", "xmip").timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let receiver = std::thread::spawn(move || {
            // Two transports, so two sessions: each keeps its own.
            let near = || {
                PostgresTransport::new(address.clone(), "orders", "xmip").timing_out_after(secs(2))
            };
            let bytes = near().receive().and_then(verdicts);
            (bytes, near().receive().and_then(verdicts))
        });
        let rows: [&[Option<&str>]; 1] = [&[Some("1"), Some(HEX_FFFE)]];
        let mut session = accept_one(&far_end, &listener)
            .expect("first")
            .with_table(&["id", "payload"], &rows);
        while session.next_event().expect("event").is_some() {}
        let text: [&[Option<&str>]; 1] = [&[Some("2"), Some("ISA*00*")]];
        let mut session = accept_one(&far_end, &listener)
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
    fn a_server_asking_for_scram_or_speaking_nonsense_is_refused() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address").to_string();
        std::thread::spawn(move || {
            let asking = |method| encode_backend(&Backend::Authentication(method));
            for answer in [
                &asking(AUTH_SASL)[..],
                &asking(AUTH_CLEARTEXT)[..],
                b"HTTP/1.1 400 Bad Request\r\n\r\n",
            ] {
                let (mut stream, _) = listener.accept().expect("accept");
                let mut sink = [0u8; 1024];
                let _ = std::io::Read::read(&mut stream, &mut sink);
                std::io::Write::write_all(&mut stream, answer).expect("write");
                let _ = std::io::Read::read(&mut stream, &mut sink);
            }
        });
        let near = PostgresTransport::new(address, "orders", "xmip").timing_out_after(secs(2));
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
