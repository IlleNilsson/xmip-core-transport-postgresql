//! The server's side of one connection: what a test puts at the far end,
//! and what the playground drives.
//!
//! Not a database. One session does the login for one client — trust, or
//! a cleartext password it demands and checks — and answers each query
//! from a closure or from one fixed table: any SELECT gets the table's
//! rows, an INSERT of one column is recorded as a Stream — read from its
//! literal as the column is declared to hold it, and refused as invalid
//! input where the literal is not that — anything else is completed with
//! its own verb. Planning, storage and SQL are a database's.

use std::io::{BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use sql::{Literal, POSTGRESQL, Verb};
use transport::Taken;
use transport::error::{Result, TransportError, classify, protocol_error};
use transport::socket;
use transport::sql::{Answering, Column, Inserted, Rows, next_insert, table};

use crate::backend::{Backend, encode_backend};
use crate::frontend::{Frontend, read_frontend, read_startup};
use crate::wire::{AUTH_CLEARTEXT, AUTH_OK};

/// What the client did, as [`Session::next_event`] reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The client ran a SELECT; here it is.
    Selected(String),
    /// The client inserted one value; here is the Stream.
    Inserted(Taken),
    /// The client ran something else; here it is.
    Executed(String),
}

impl Inserted for Event {
    fn inserted(self) -> Option<Taken> {
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
    column: Column,
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
            column: Column::Binary,
        };
        session.startup()?;
        if let Some(expected) = password {
            session.write(&Backend::Authentication(AUTH_CLEARTEXT))?;
            let Some(Frontend::Password(given)) = read_frontend(&mut session.reader)? else {
                return Err(protocol_error("the client did not answer with a password"));
            };
            if !codec::constant_time::equal(given.as_bytes(), expected.as_bytes()) {
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

    /// What the column an INSERT names holds: bytes unless declared
    /// otherwise.
    #[must_use]
    pub const fn holding(mut self, column: Column) -> Self {
        self.column = column;
        self
    }

    /// Answer any SELECT with these `columns` and `rows`.
    #[must_use]
    pub fn with_table(mut self, columns: &[&str], rows: &[&[Option<&str>]]) -> Self {
        (self.columns, self.rows) = table(columns, rows);
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
    pub fn next_insert(&mut self) -> Result<Option<Taken>> {
        next_insert(|| self.next_event())
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
        let verb = Verb::of_statement(sql);
        match verb {
            Some(Verb::Select) => (
                Answer::Rows {
                    columns: self.columns.clone(),
                    rows: self.rows.clone(),
                },
                Event::Selected(sql.to_string()),
            ),
            Some(Verb::Insert) => match POSTGRESQL.parse_insert_literal(sql) {
                Some((table, column, Literal::Text(value))) => {
                    let origin = format!(
                        "postgresql://{}/{}/{table}/{column}",
                        self.peer, self.database
                    );
                    match self.column.bytes(&value, &POSTGRESQL) {
                        Ok(bytes) => (
                            Answer::Complete("INSERT 0 1".to_string()),
                            Event::Inserted(Taken::new(origin, bytes)),
                        ),
                        Err(refused) => (
                            Answer::Error {
                                code: "22P02".to_string(),
                                message: refused.message,
                            },
                            Event::Executed(sql.to_string()),
                        ),
                    }
                }
                _ => (
                    Answer::Error {
                        code: "42601".to_string(),
                        message: "only INSERT INTO t (c) VALUES ('v') is served here".to_string(),
                    },
                    Event::Executed(sql.to_string()),
                ),
            },
            _ => {
                // The command tag names the verb, as the server's does.
                let tag = verb.map_or_else(String::new, |verb| verb.name().to_ascii_uppercase());
                (Answer::Complete(tag), Event::Executed(sql.to_string()))
            }
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
