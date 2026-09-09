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

use transport::Arrived;
use transport::error::{Result, TransportError, classify, protocol_error};
use transport::socket;

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

type Answering = Box<dyn FnMut(&str) -> Option<Answer> + Send>;

pub struct Session {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    peer: SocketAddr,
    user: String,
    database: String,
    columns: Vec<String>,
    rows: Vec<Vec<Option<String>>>,
    answering: Option<Answering>,
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
        self.columns = columns.iter().map(ToString::to_string).collect();
        self.rows = rows
            .iter()
            .map(|row| row.iter().map(|v| v.map(String::from)).collect())
            .collect();
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
        loop {
            match self.next_event()? {
                Some(Event::Inserted(arrived)) => return Ok(Some(arrived)),
                Some(_) => {}
                None => return Ok(None),
            }
        }
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
        let verb = sql
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
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
                        Event::Inserted(Arrived::new(origin, value.into_bytes())),
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
/// Identifiers may be quoted; anything else is `None`.
#[must_use]
pub fn parse_insert(sql: &str) -> Option<(String, String, String)> {
    let rest = sql.trim().trim_end_matches(';');
    let rest = strip_word(rest, "INSERT")?;
    let rest = strip_word(rest, "INTO")?;
    let (table, rest) = identifier(rest)?;
    let rest = rest.trim_start().strip_prefix('(')?;
    let (column, rest) = identifier(rest)?;
    let rest = rest.trim_start().strip_prefix(')')?;
    let rest = strip_word(rest, "VALUES")?;
    let rest = rest.trim_start().strip_prefix('(')?.trim_start();
    let rest = rest.strip_prefix('\'')?;
    let mut value = String::new();
    let mut chars = rest.chars().peekable();
    loop {
        match chars.next()? {
            '\'' if chars.peek() == Some(&'\'') => {
                chars.next();
                value.push('\'');
            }
            '\'' => break,
            other => value.push(other),
        }
    }
    let tail: String = chars.collect();
    (tail.trim() == ")").then_some((table, column, value))
}

fn strip_word<'a>(rest: &'a str, word: &str) -> Option<&'a str> {
    let rest = rest.trim_start();
    let head = rest.get(..word.len())?;
    head.eq_ignore_ascii_case(word).then(|| &rest[word.len()..])
}

/// One identifier, bare or double-quoted, and what follows it.
fn identifier(rest: &str) -> Option<(String, &str)> {
    let rest = rest.trim_start();
    if let Some(quoted) = rest.strip_prefix('"') {
        let end = quoted.find('"')?;
        return Some((quoted[..end].to_string(), &quoted[end + 1..]));
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
            parse_insert("INSERT INTO public.inbox (payload) VALUES ('a\nb')"),
            Some(("public.inbox".into(), "payload".into(), "a\nb".into()))
        );
        assert!(parse_insert("INSERT INTO inbox (a, b) VALUES ('x', 'y')").is_none());
        assert!(parse_insert("INSERT INTO inbox (a) VALUES ('open").is_none());
        assert!(parse_insert("UPDATE inbox SET a = 'x'").is_none());
    }
}
