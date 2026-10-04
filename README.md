# xmip-core-transport-postgresql

PostgreSQL transport: the frontend/backend protocol 3.0 in its simple query
flow — a Receive Location runs a query and each row is a Stream, a Send
Location inserts a Stream as a row; trust and cleartext login. A technology of
[xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

## Acknowledgement

The Location's query only reads; what consumes a row is the `accept` statement, run after the row's receive cycle. `accept` (text, receive side, optional) is a statement — `DELETE FROM inbox WHERE id = $1`, an `UPDATE` of a status column — with the row's name, the query's first column as the origin carries it, in place of `$1`, written as a string literal by `quote_literal` (`transport::sql::accept`, the marker `$1` being `PostgreSQL`'s first parameter), so whatever the column holds stays one value. It runs on the connection kept for the server and database:

- **Accepted**: `accept` runs; the row is consumed once its Stream is Xmip's.
- **Refused**: nothing runs. A refusal is not a consumption: the row is the only copy, so it is left where it lies, and this Location does not receive it again while its body is unchanged; a row whose body changed is a new arrival. The memory is the node process's (`transport::refused`).
- **Failed**: nothing runs, and the next receive reads the row again.

A row whose first column is NULL has no name to bind, and nothing runs for it. Where `accept` is left out a row's verdict tells the database nothing: every row is read again unless the query keeps it from that, and a query that consumes as it reads — a `DELETE … RETURNING` — consumes before the receive cycle has run: acceptance is then at-most-once. Each statement is one round trip per accepted row, on the kept connection. Each row is a whole value of the result, read whole.

The double-quoted identifiers and string literals it writes and its far end reads are
`xmip-core-library-codec`'s `sql` module, the one SQL quoting in the estate;
which delimiter is this dialect's own.

Where a send target puts its row — `<scheme>://host:port/<catalog>/<table>/<column>`,
`host:port/<catalog>/<table>/<column>` or `<table>/<column>` — and the one
INSERT, its table and column always quoted identifiers so a target can name
nothing but them, are `xmip-core-transport`'s `sql` module; this crate hands
it its `DIALECT`: the schemes `postgresql` and `postgres`, a database, double quotes.

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

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
