# ADR 0003: IPC Wire Protocol

## Status

Accepted.

## Context

The daemon and shell need a local IPC protocol. The codebase already
has a `.proto` file (`sysknife-proto`) with message definitions for
`RequestEnvelope`, `PreviewEnvelope`, `ResultEnvelope`, and
`TransactionRecord`, and a `bind_unix_listener` helper. The question
is what framing and encoding to use over the Unix domain socket.

Candidates considered:

1. **gRPC over Unix socket** — uses the proto definitions directly
   with `tonic`. Full service interface. Requires HTTP/2 and a
   `service` block in the proto.
2. **Length-prefixed protobuf** — binary, compact. Requires a
   custom dispatcher (no HTTP/2). Harder to inspect without tooling.
3. **Length-prefixed JSON** — 4-byte LE `u32` length + UTF-8 JSON
   body. Uses the same Rust structs (`sysknife-types`) already tested for
   serialization. Human-readable, easy to debug with `socat`.

## Decision

Use **length-prefixed JSON** (option 3) for the Unix socket protocol.

Each message carries a `"type"` discriminant string so the dispatcher
can route without a full decode. The `sysknife-types` structs are reused
as-is — no additional generated code or build-time proto compilation
beyond what already exists.

The proto definitions in `sysknife-proto` are kept for potential future
use (e.g., a networked or gRPC-based control plane) but are not the
primary on-wire encoding for local IPC.

## Consequences

- No new build-time dependencies for the daemon or shell.
- Messages are inspectable with standard tools (`socat`, `nc`, `jq`).
- A framing crate is not needed — `tokio::io::AsyncReadExt::read_exact`
  is sufficient.
- If a binary protocol is needed later (performance, cross-language
  clients), the socket path changes and both sides are updated together.
  There are no external clients to coordinate with.
