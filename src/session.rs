//! The server's side of one connection: what a test puts at the far end,
//! and what the playground drives.
//!
//! Not a database. One session does the login for one client — trust, or
//! a cleartext password it demands and checks — and answers each query
//! from a closure or from one fixed table: any SELECT gets the table's
//! rows, an INSERT of one column is recorded as a Stream, anything else is
//! completed with its own verb. Planning, storage and SQL are a database's.

use std::io::{BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use codec::sql::Delimiter;
use transport::Arrived;
use transport::error::{Result, TransportError, classify, protocol_error};
use transport::socket;
use transport::sql::{self, Answering, Inserted, Rows};

use crate::backend::{Backend, encode_backend};
use crate::frontend::{Frontend, read_frontend, read_startup};
use crate::wire::{AUTH_CLEARTEXT, AUTH_OK};

/// What the client did, as [`Session::next_event`] reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The client ran a SELECT; here it is.
    Selected(String),
    /// The client inserted one value; here is the Stream.
    Inserted(Arrived),
    /// The client ran something else; here it is.
    Executed(String),
}

impl Inserted for Event {
    fn inserted(self) -> Option<Arrived> {
        match self {
            Self::Inserted(arrived) => Some(arrived),
            Self::Selected(_) | Self::Executed(_) => None,
        }
    }
}

/// How a query is answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    Rows {
        columns: Vec<String>,
        rows: Vec<Vec<Option<String>>>,
    },
    Complete(String),
    Error {
        code: String,
        message: String,
    },
}

pub struct Session {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    peer: SocketAddr,
    user: String,
    database: String,
    columns: Vec<String>,
    rows: Rows<String>,
    answering: Option<Answering<Answer>>,
}

impl Session {
    /// Accept one client on `listener` and log it in: with `password`, by
    /// demanding it in the clear and checking; without, by trust.
    ///
    /// # Errors
    /// Where the connection could not be accepted, the client did not open
    /// with a startup message, or gave the wrong password — which is told
    /// to the client as `28P01` before this returns.
    pub fn accept(
        listener: &TcpListener,
        password: Option<&str>,
        timeout: Option<Duration>,
    ) -> Result<Self> {
        let (stream, peer) = socket::accept_tcp(listener, timeout)?;
        let (reader, writer) = socket::split(stream)?;
        let mut session = Self {
            reader,
            writer,
            peer,
            user: String::new(),
            database: String::new(),
            columns: Vec::new(),
            rows: Vec::new(),
            answering: None,
        };
        session.startup()?;
        if let Some(expected) = password {
            session.write(&Backend::Authentication(AUTH_CLEARTEXT))?;
            let Some(Frontend::Password(given)) = read_frontend(&mut session.reader)? else {
                return Err(protocol_error("the client did not answer with a password"));
            };
            if given != expected {
                let message = format!(
                    "password authentication failed for user \"{}\"",
                    session.user
                );
                session.write(&Backend::ErrorResponse {
                    severity: "FATAL".to_string(),
                    code: "28P01".to_string(),
                    message: message.clone(),
                })?;
                return Err(TransportError::permanent(message));
            }
        }
        session.write(&Backend::Authentication(AUTH_OK))?;
        session.write(&Backend::ParameterStatus {
            name: "server_version".to_string(),
            value: "16.0 (xmip)".to_string(),
        })?;
        session.write(&Backend::BackendKeyData {
            process: 1,
            secret: 0,
        })?;
        session.write(&Backend::ReadyForQuery(b'I'))?;
        Ok(session)
    }

    /// The startup message, a request for TLS declined on the way.
    fn startup(&mut self) -> Result<()> {
        loop {
            match read_startup(&mut self.reader)? {
                Some(Frontend::SslRequest) => self
                    .writer
                    .write_all(b"N")
                    .map_err(|e| classify("declining TLS", &e))?,
                Some(Frontend::Startup { user, database }) => {
                    self.user = user;
                    self.database = database;
                    return Ok(());
                }
                _ => {
                    return Err(protocol_error(
                        "the client did not open with a startup message",
                    ));
                }
            }
        }
    }

    /// The user the client logged in as.
    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }

    /// The database the client asked for.
    #[must_use]
    pub fn database(&self) -> &str {
        &self.database
    }

    /// Answer any SELECT with these `columns` and `rows`.
    #[must_use]
    pub fn with_table(mut self, columns: &[&str], rows: &[&[Option<&str>]]) -> Self {
        (self.columns, self.rows) = sql::table(columns, rows);
        self
    }

    /// Answer queries with `answering` first; what it declines falls to the
    /// table.
    #[must_use]
    pub fn answering(
        mut self,
        answering: impl FnMut(&str) -> Option<Answer> + Send + 'static,
    ) -> Self {
        self.answering = Some(Box::new(answering));
        self
    }

    /// The next value the client inserts, or `None` when it closed.
    /// Everything else is answered on the way.
    ///
    /// # Errors
    /// Where the connection broke, or nothing arrived before the timeout.
    pub fn next_insert(&mut self) -> Result<Option<Arrived>> {
        sql::next_insert(|| self.next_event())
    }

    /// The next query the client ran, answered, or `None` when it closed.
    ///
    /// # Errors
    /// Where the connection broke, nothing arrived before the timeout, or
    /// the client sent what the simple flow does not.
    pub fn next_event(&mut self) -> Result<Option<Event>> {
        loop {
            match read_frontend(&mut self.reader)? {
                Some(Frontend::Query(sql)) => {
                    let (answer, event) = self.answer(&sql);
                    self.write_answer(&answer)?;
                    self.write(&Backend::ReadyForQuery(b'I'))?;
                    return Ok(Some(event));
                }
                Some(Frontend::Terminate) | None => return Ok(None),
                Some(Frontend::Password(_)) => {}
                Some(other) => {
                    return Err(protocol_error(format!("{other:?} after the login")));
                }
            }
        }
    }

    fn answer(&mut self, sql: &str) -> (Answer, Event) {
        if let Some(answer) = self.answering.as_mut().and_then(|f| f(sql)) {
            return (answer, Event::Executed(sql.to_string()));
        }
        let verb = sql::verb(sql);
        match verb.as_str() {
            "SELECT" => (
                Answer::Rows {
                    columns: self.columns.clone(),
                    rows: self.rows.clone(),
                },
                Event::Selected(sql.to_string()),
            ),
            "INSERT" => match parse_insert(sql) {
                Some((table, column, value)) => {
                    let origin = format!(
                        "postgresql://{}/{}/{table}/{column}",
                        self.peer, self.database
                    );
                    (
                        Answer::Complete("INSERT 0 1".to_string()),
                        Event::Inserted(Arrived::new(origin, crate::bytea::column_bytes(value))),
                    )
                }
                None => (
                    Answer::Error {
                        code: "42601".to_string(),
                        message: "only INSERT INTO t (c) VALUES ('v') is served here".to_string(),
                    },
                    Event::Executed(sql.to_string()),
                ),
            },
            _ => (Answer::Complete(verb), Event::Executed(sql.to_string())),
        }
    }

    fn write_answer(&mut self, answer: &Answer) -> Result<()> {
        match answer {
            Answer::Rows { columns, rows } => {
                self.write(&Backend::RowDescription(columns.clone()))?;
                for row in rows {
                    self.write(&Backend::DataRow(row.clone()))?;
                }
                self.write(&Backend::CommandComplete(format!("SELECT {}", rows.len())))
            }
            Answer::Complete(tag) => self.write(&Backend::CommandComplete(tag.clone())),
            Answer::Error { code, message } => self.write(&Backend::ErrorResponse {
                severity: "ERROR".to_string(),
                code: code.clone(),
                message: message.clone(),
            }),
        }
    }

    fn write(&mut self, message: &Backend) -> Result<()> {
        self.writer
            .write_all(&encode_backend(message))
            .map_err(|e| classify("writing a message", &e))?;
        self.writer
            .flush()
            .map_err(|e| classify("flushing a message", &e))
    }
}

/// `INSERT INTO <table> (<column>) VALUES ('<literal>')` taken apart:
/// the table, the column and the literal with its quotes undoubled.
/// Identifiers may be quoted; anything else is `None`. The statement's
/// shape is the capability's (`transport::sql`, ADR-0044); the quoting is
/// this dialect's.
#[must_use]
pub fn parse_insert(statement: &str) -> Option<(String, String, String)> {
    sql::parse_insert(statement, identifier, literal)
}

/// One `'…'` literal with its quotes undoubled, and what follows it.
fn literal(rest: &str) -> Option<(String, &str)> {
    Delimiter::STRING.unquote_prefix(rest).ok()
}

/// One identifier, bare or double-quoted with `""` for a quote, and what
/// follows it.
fn identifier(rest: &str) -> Option<(String, &str)> {
    let rest = rest.trim_start();
    if rest.starts_with('"') {
        return Delimiter::IDENTIFIER.unquote_prefix(rest).ok();
    }
    let end = rest
        .find(|c: char| !(c.is_alphanumeric() || c == '_' || c == '.'))
        .unwrap_or(rest.len());
    (end > 0).then(|| (rest[..end].to_string(), &rest[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_insert_of_one_column_is_taken_apart() {
        assert_eq!(
            parse_insert("INSERT INTO inbox (payload) VALUES ('it''s here');"),
            Some(("inbox".into(), "payload".into(), "it's here".into()))
        );
        assert_eq!(
            parse_insert("insert into \"In box\" ( \"Payload\" ) values ( '' )"),
            Some(("In box".into(), "Payload".into(), String::new()))
        );
        assert_eq!(
            parse_insert("INSERT INTO \"in\"\"box\" (\"a\") VALUES ('x')"),
            Some(("in\"box".into(), "a".into(), "x".into())),
            "a doubled quote is one, as quote_identifier writes it"
        );
        assert_eq!(
            parse_insert("INSERT INTO public.inbox (payload) VALUES ('a\nb')"),
            Some(("public.inbox".into(), "payload".into(), "a\nb".into()))
        );
        assert!(parse_insert("INSERT INTO inbox (a, b) VALUES ('x', 'y')").is_none());
        assert!(parse_insert("INSERT INTO inbox (a) VALUES ('open").is_none());
        assert!(parse_insert("UPDATE inbox SET a = 'x'").is_none());
    }
}
