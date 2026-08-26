# PAYPHONE

![PAYPHONE encrypted tunnel overview](assets/24b36d7a-c887-4b15-83f3-42c6abd586b3.png)

PAYPHONE is an experimental encrypted session protocol built on top of QUIC and TLS 1.3. The repository contains a small client/server demo that negotiates a logical session, exchanges application datagrams, performs a keepalive check, and can resume a recently disconnected session.

> [!WARNING]
> PAYPHONE is a development prototype, not a production-ready VPN. The current `DATA` payload contains demo text; TUN integration, packet routing, rekeying, and graceful protocol-level shutdown are not implemented yet.

## Features

- QUIC datagram transport provided by [Quinn](https://github.com/quinn-rs/quinn)
- TLS 1.3 with a self-signed development certificate
- Versioned binary wire format with payload-size validation
- Capability negotiation during the initial handshake
- Logical session IDs and assigned private IPv4 addresses
- Session resumption using a locally stored resume token
- `DATA` request/response exchange
- `PING`/`PONG` keepalive exchange
- Concurrent Tokio-based server
- Unit tests for frame encoding, messages, sessions, and transport setup

## Workspace layout

| Crate | Purpose |
| --- | --- |
| `payphone-core` | Wire frames, protocol messages, constants, codecs, and validation |
| `payphone-transport` | QUIC client/server endpoints and development TLS identity management |
| `payphone-server` | Session management and server-side frame handling |
| `payphone-client` | Demo client covering handshake, data transfer, keepalive, and session resume |

## Protocol overview

Every PAYPHONE message is carried in a QUIC datagram and starts with a 16-byte header:

| Field | Size |
| --- | ---: |
| Protocol version | 1 byte |
| Frame type | 1 byte |
| Flags | 2 bytes |
| Payload length | 4 bytes |
| Sequence number | 8 bytes |

Protocol version 1 defines these frame types:

| Value | Frame | Direction | Status |
| ---: | --- | --- | --- |
| 1 | `Data` | Both | Implemented |
| 2 | `WhatsUpDude` | Client to server | Implemented |
| 3 | `AllGoodDude` | Server to client | Implemented |
| 4 | `Ping` | Client to server | Implemented |
| 5 | `Pong` | Server to client | Implemented |
| 6 | `Rekey` | Both | Reserved |
| 7 | `Close` | Both | Reserved |
| 8 | `BackAgainDude` | Client to server | Implemented |
| 9 | `StillGoodDude` | Server to client | Implemented |

The maximum frame payload is 64 KiB. Multi-byte integers are encoded in network byte order.

### Session flow

```text
Client                                  Server
  |                                       |
  |---- WhatsUpDude --------------------->|  create session
  |<--- AllGoodDude ----------------------|  session ID, IPv4, token
  |                                       |
  |---- Data ---------------------------->|
  |<--- Data -----------------------------|
  |                                       |
  |---- Ping ---------------------------->|
  |<--- Pong -----------------------------|
  |                                       |
  |---- BackAgainDude ------------------->|  reconnect with saved token
  |<--- StillGoodDude --------------------|  resume the same session
```

## Requirements

- Rust 1.85 or newer (the workspace uses the Rust 2024 edition)
- A platform that supports UDP sockets

Install Rust with [rustup](https://rustup.rs/) if it is not already available.

## Quick start

Run all commands from the repository root because the development certificate and session files use paths relative to the current directory.

1. Start the server:

   ```bash
   cargo run -p payphone-server
   ```

   The server listens on `127.0.0.1:40404`. If necessary, it creates the development identity in `dev-certs/`.

2. In another terminal, run the client:

   ```bash
   cargo run -p payphone-client
   ```

   The client connects over QUIC/TLS, creates or resumes a session, exchanges one demo `DATA` message, verifies the connection with `PING`/`PONG`, and exits.

3. Run the client again within 30 seconds to see session resumption:

   ```bash
   cargo run -p payphone-client
   ```

The client stores its session ID and resume token in `.payphone-session`. Sessions exist only in server memory and expire after 30 seconds without valid `DATA` or `PING` traffic. Restarting the server also invalidates all sessions.

To force a fresh handshake, remove `.payphone-session` before starting the client.

## Testing

Run the complete test suite with:

```bash
cargo test --workspace
```

The transport tests open a local UDP socket, so they must run in an environment that permits local network binding.

## Development notes

- The server currently supports IPv4, DNS, and session-resume capabilities. The client advertises IPv4, IPv6, DNS, resume, and roaming; the handshake keeps only the capabilities supported by both sides.
- New sessions receive addresses from the development range `10.77.0.0/24`, starting at `10.77.0.2`.
- The negotiated demo MTU is 1280 bytes.
- The server binds only to localhost. Change the bind address deliberately before testing across machines.
- `Rekey` and protocol-level `Close` frames are defined but not implemented.

## Security notice

The files in `dev-certs/` are development credentials. The private key is included in the repository, and the client stores its resume token as unencrypted local bytes. Do not reuse these credentials or this storage approach in production.
