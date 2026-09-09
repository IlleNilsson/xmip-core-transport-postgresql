//! The client's side of one connection to a server: the login, a query
//! and its rows, a statement and its tag. Text format only, which is what
//! the simple query flow gives.

use std::io::{BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

use transport::error::{Result, TransportError, classify, protocol_error};
use transport::socket;

use crate::backend::{Backend, read_backend};
use crate::frontend::{Frontend, encode_frontend};
use crate::wire::{AUTH_CLEARTEXT, AUTH_MD5, AUTH_OK, AUTH_SASL};

/// What a query came back with.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QueryResult {
    pub columns: Vec<String>,
    /// Each row, each column as text or NULL.
    pub rows: Vec<Vec<Option<String>>>,
    /// `SELECT 3`, `INSERT 0 1`.
    pub tag: String,
}

pub struct Client {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    parameters: Vec<(String, String)>,
}

impl Client {
    /// Connect to `server` as `user` on `database`, giving `password` where
    /// the server asks for it in the clear.
    ///
    /// # Errors
    /// Where the server could not be reached, refused the login, or asks
    /// for MD5 or SCRAM, which this crate does not speak.
    pub fn connect(
        server: &str,
        user: &str,
        database: &str,
        password: Option<&str>,
        timeout: Option<Duration>,
    ) -> Result<Self> {
        let stream = socket::connect_tcp(server, timeout)?;
        let (reader, writer) = socket::split(stream)?;
        let mut client = Self {
            reader,
            writer,
            parameters: Vec::new(),
        };
        client.write(&Frontend::Startup {
            user: user.to_string(),
            database: database.to_string(),
        })?;
        loop {
            match read_backend(&mut client.reader)? {
                Some(Backend::Authentication(AUTH_OK)) => {}
                Some(Backend::Authentication(AUTH_CLEARTEXT)) => {
                    let Some(password) = password else {
                        return Err(TransportError::permanent(
                            "the server asks for a password and none is configured",
                        ));
                    };
                    client.write(&Frontend::Password(password.to_string()))?;
                }
                Some(Backend::Authentication(method)) => {
                    let name = match method {
                        AUTH_MD5 => "MD5".to_string(),
                        AUTH_SASL => "SCRAM".to_string(),
                        other => format!("method {other}"),
                    };
                    return Err(TransportError::permanent(format!(
                        "the server asks for {name}, and this crate speaks trust and cleartext only"
                    )));
                }
                Some(Backend::ParameterStatus { name, value }) => {
                    client.parameters.push((name, value));
                }
                Some(Backend::ReadyForQuery(_)) => return Ok(client),
                Some(Backend::ErrorResponse { code, message, .. }) => {
                    return Err(sql_error(&code, &message));
                }
                Some(_) => {}
                None => return Err(protocol_error("the server closed during the login")),
            }
        }
    }

    /// A parameter the server reported at login, `server_version` say.
    #[must_use]
    pub fn parameter(&self, name: &str) -> Option<&str> {
        self.parameters
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// Run `sql` and take its rows.
    ///
    /// # Errors
    /// Where the server went away or answered with an error.
    pub fn query(&mut self, sql: &str) -> Result<QueryResult> {
        self.write(&Frontend::Query(sql.to_string()))?;
        let mut result = QueryResult::default();
        let mut failed = None;
        loop {
            match read_backend(&mut self.reader)? {
                Some(Backend::RowDescription(columns)) => result.columns = columns,
                Some(Backend::DataRow(values)) => result.rows.push(values),
                Some(Backend::CommandComplete(tag)) => result.tag = tag,
                Some(Backend::ErrorResponse { code, message, .. }) => {
                    failed = Some(sql_error(&code, &message));
                }
                Some(Backend::ReadyForQuery(_)) => {
                    return failed.map_or(Ok(result), Err);
                }
                Some(_) => {}
                None => return Err(protocol_error("the server closed mid-query")),
            }
        }
    }

    /// Run `sql` for its effect; the tag the server completed it with.
    ///
    /// # Errors
    /// Where the server went away or answered with an error.
    pub fn execute(&mut self, sql: &str) -> Result<String> {
        self.query(sql).map(|result| result.tag)
    }

    /// Say goodbye and hang up.
    ///
    /// # Errors
    /// Where the server had already gone.
    pub fn close(mut self) -> Result<()> {
        self.write(&Frontend::Terminate)
    }

    fn write(&mut self, message: &Frontend) -> Result<()> {
        self.writer
            .write_all(&encode_frontend(message))
            .map_err(|e| classify("writing a message", &e))?;
        self.writer
            .flush()
            .map_err(|e| classify("flushing a message", &e))
    }
}

/// An error the server answered, retryable where its SQLSTATE class says
/// the trouble is the connection, a rollback, a resource or an operator —
/// what a later attempt might not meet.
#[must_use]
pub fn sql_error(code: &str, message: &str) -> TransportError {
    let text = format!("the server answered {code}: {message}");
    match code.get(..2) {
        Some("08" | "40" | "53" | "57") => TransportError::retryable(text),
        _ => TransportError::permanent(text),
    }
}

/// `text` as a string literal: quoted, every quote doubled. Backslashes
/// are literal, as `standard_conforming_strings` has had them since 9.1.
#[must_use]
pub fn quote_literal(text: &str) -> String {
    format!("'{}'", text.replace('\'', "''"))
}

/// `name` as an identifier: quoted, every quote doubled, case kept.
#[must_use]
pub fn quote_identifier(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_doubles_the_delimiter_and_nothing_else() {
        assert_eq!(quote_literal("it's"), "'it''s'");
        assert_eq!(quote_literal("back\\slash"), "'back\\slash'");
        assert_eq!(quote_literal(""), "''");
        assert_eq!(quote_identifier("in\"box"), "\"in\"\"box\"");
        assert_eq!(quote_identifier("Inbox"), "\"Inbox\"");
    }

    #[test]
    fn an_error_is_judged_by_its_class() {
        assert!(sql_error("08006", "connection failure").retryable);
        assert!(sql_error("40P01", "deadlock detected").retryable);
        assert!(sql_error("57P03", "the database system is starting up").retryable);
        assert!(!sql_error("28P01", "password authentication failed").retryable);
        assert!(!sql_error("42P01", "relation does not exist").retryable);
        assert!(!sql_error("", "nothing").retryable);
    }
}
