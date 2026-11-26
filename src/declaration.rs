//! What a Location of this technology is configured with: its declaration,
//! which its wire hands `transport::sql`'s `Configured`, built with the
//! crate's `declaration` feature alone and the code behind the default
//! (ADR-0064, amendments 2026-10-22 and 2026-11-26), for the library the
//! surfaces load to carry (open problem 48): what every SQL Location
//! declares (`transport::sql`).

use transport::sql::accept::ACCEPT;
use transport::sql::{COLUMN, DATABASE, ENCODING, QUERY, TIMEOUT, USER};
use xcore::settings::Settings;

/// Every setting a `PostgreSQL` Location takes beyond its address, the
/// server's host and port: where a Location connects.
pub const SETTINGS: &Settings = &Settings {
    technology: env!("CARGO_PKG_NAME"),
    settings: &[USER, DATABASE, QUERY, ACCEPT, COLUMN, ENCODING, TIMEOUT],
};

/// The schemes a Location's address is entered with to choose this technology.
pub const SCHEMES: &[&str] = &["postgresql", "postgres"];
