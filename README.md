# xmip-core-transport-postgresql

PostgreSQL transport: a Receive Location runs a query and each row is a
Stream, a Send Location inserts a Stream as a row; trust and cleartext login.
A technology of
[xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

The transport is every SQL technology's, `transport::sql::SqlTransport`, over
this crate's `PostgreSql` wire (2026-11-13): its name and schemes, its
settings, the PostgreSQL dialect, the client, and the far end its loopback
serves (`accept_one`, `taken`). The protocol — the frontend/backend protocol
3.0 in its simple query flow, both halves — is
[xmip-core-library-postgresql](https://github.com/IlleNilsson/xmip-core-library-postgresql)'s,
which the archive target speaks too; until 2026-11-13 it sat here.

## Acknowledgement

`accept` is every SQL technology's (`transport::sql::accept`): [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport)'s README. On `PostgreSQL` it is a statement — `DELETE FROM inbox WHERE id = $1`, an `UPDATE` of a status column — with the row's name in place of `$1`, `PostgreSQL`'s first parameter, written as `PostgreSQL`'s string literal; it runs on the connection kept for the server and database, one round trip per accepted row. A query that consumes as it reads is a `DELETE … RETURNING`.

The SQL it writes and its far end reads — double-quoted identifiers, string
literals, the bytea hex form, the one INSERT with its table and column
always quoted identifiers so a target can name nothing but them, and a
statement's verb — is `PostgreSQL`'s as `xmip-core-library-sql` writes it
(`sql::POSTGRESQL`), the one SQL in the estate.

Where a send target puts its row — `<scheme>://host:port/<database>/<table>/<column>`,
`host:port/<database>/<table>/<column>` or `<table>/<column>` — is
`xmip-core-transport`'s `sql` module; this crate hands it its schemes,
`postgresql` and `postgres`.

The payload column holds bytes unless the Location declares otherwise (ADR-0038:
a payload is bytes). `column = "binary"`, the default, writes every Stream in
the dialect's binary form (the bytea hex form, `\x…`) and reads a value back only from that form;
`column = "text"` decodes the Stream strictly in its `encoding` — `utf-8`
unless `utf-16le`, `utf-16be`, `utf-32le` or `utf-32be` is named — writes it as
a string literal, and encodes a value read back to that form. A Stream or a
value that is not its declared form is refused, never repaired. The two
settings and the rule are `xmip-core-transport`'s `sql` module, shared by every
SQL transport.

A Send Location inserts on a connection logged in once per server and database and kept (`transport::Pool`). Until 2026-09-27 every insert logged in and terminated.

A Receive Location runs its query on a connection kept the same way: logged in on its first receive and reused by every receive after, replaced where the server closed it. Until 2026-09-28 every receive logged in and terminated.

## The declaration

What a Location of this technology is configured with is two `const`s in its `declaration` module, `src/declaration.rs`, beside the code, which its wire hands `transport::sql`'s `Configured` (ADR-0064, amendment 2026-11-26): `declaration::SETTINGS`, `user`, `database`, `query`, `accept`, `column`, `encoding` and `timeout`, each what every SQL Location declares (`transport::sql`), and `SCHEMES`, `postgresql` and `postgres`. Built with its `declaration` feature alone (`--no-default-features --features declaration`), the crate is those and nothing more: its code and every crate the code is built on — the protocol and the dialect — are behind the default feature. So the library the surfaces load carries it without the code, through the gathering crate xmip-core-declaration (open problem 48), and the language server and the desktop suggest and check a `PostgreSQL` Location's settings though no node in their process loaded the technology. `test/Declaration.Test.ps1` in the estate holds that the declaration builds nothing the transport capability does not.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
