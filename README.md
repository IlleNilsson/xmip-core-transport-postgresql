# xmip-core-transport-postgresql

PostgreSQL transport: the frontend/backend protocol 3.0 in its simple query
flow — a Receive Location runs a query and each row is a Stream, a Send
Location inserts a Stream as a row; trust and cleartext login. A technology of
[xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

The double-quoted identifiers and string literals it writes and its far end reads are
`xmip-core-library-codec`'s `sql` module, the one SQL quoting in the estate;
which delimiter is this dialect's own.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
