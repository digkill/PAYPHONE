# PAYPHONE

![PAYPHONE encrypted tunnel overview](assets/24b36d7a-c887-4b15-83f3-42c6abd586b3.png)

PAYPHONE is an experimental IPv4 VPN written in Rust. It carries IP packets from a TUN interface inside QUIC datagrams, protects the transport with TLS 1.3, and authenticates new sessions with Ed25519-signed subscription tokens.

> [!WARNING]
> PAYPHONE is a development prototype, not a production-ready VPN. Self-signed TLS is the default. Set `PAYPHONE_TLS_DOMAIN=vpn.example.com` (DNS A-record to the VPS) and the server will get a Let's Encrypt certificate on TCP 443 via TLS-ALPN-01; the client then uses that hostname and public CAs (`--tls-ca system` is automatic).

## What works

- Bidirectional IPv4 packet transport between TUN interfaces
- QUIC datagrams with TLS 1.3, powered by [Quinn](https://github.com/quinn-rs/quinn)
- Compact, versioned binary frames with strict length validation
- Ed25519-signed subscription tokens with validity periods and plan metadata
- Server-side checks for signatures, activation time, expiry, signing key, and revocation
- Capability negotiation during the initial handshake
- CLI flags, `.env`, and optional `payphone.toml` for addresses, PSK, TLS, and token paths
- TLS: pin a self-signed leaf, load PEM (`--tls-cert` / `--tls-key`, reload on mtime), or Let's Encrypt (`--tls-domain` / `PAYPHONE_TLS_DOMAIN`, TLS-ALPN-01). A public SNI makes the client trust WebPKI without a pin file.
- Encrypted client resume file (`.payphone-session`)
- Logical sessions with addresses from `10.77.0.0/24`
- Session resumption after a QUIC reconnect or a server restart (sessions are stored on disk)
- Device and bandwidth limits from the subscription token
- `Close` on shutdown (frees the VPN address immediately) and `Rekey` (rotates the resume token)
- Periodic `PING`/`PONG` keepalives
- Optional client kill switch (`--kill-switch` / `PAYPHONE_KILL_SWITCH`): no Internet unless the VPN is up; default off. Ctrl+C restores the LAN.
- Source-address validation for packets received from clients
- Concurrent client handling with Tokio
- Full-tunnel routing: the server enables IPv4 forwarding + NAT for the tunnel subnet, and the client overrides its default route through the TUN interface (macOS, Linux, Windows) with IPv6 blackholed so AAAA cannot leak past the tunnel
- Token revocations on disk (`PAYPHONE_REVOKE_FILE`, `payphone-token revoke`)

## Workspace

| Crate | Purpose |
| --- | --- |
| `payphone-core` | Wire frames, protocol messages, codecs, constants, and validation |
| `payphone-auth` | Subscription claims, Ed25519 signatures, key rings, and token verification |
| `payphone-token` | CLI for generating signing keys and issuing subscription tokens |
| `payphone-transport` | QUIC endpoints, TLS (pin / PEM / Let's Encrypt), REALITY |
| `payphone-tun` | Async TUN creation and IPv4 header helpers |
| `payphone-server` | Authentication, session management, TUN routing, and QUIC server |
| `payphone-client` | Authenticated VPN client, TUN forwarding, keepalive, and resume logic |

## Requirements

- Rust 1.85 or newer (Rust 2024 edition)
- macOS, Linux, or Windows with TUN support (Windows: `wintun.dll` next to the client, run as Administrator)
- Permission to create and configure TUN interfaces
- Local UDP port `40404` available

The current zero-configuration demo is best suited to macOS because the OS assigns separate `utunN` names automatically. On Linux, both binaries request an interface named `payphone0`; running both on one host therefore requires network namespaces or a code/configuration change.

## Quick start

All commands must be run from the repository root. Runtime files are resolved relative to the current working directory.

### 1. Build the workspace

```bash
cargo build --workspace
```

### 2. Create a development subscription

Generate an Ed25519 key pair and issue a 30-day Pro token:

```bash
cargo run -p payphone-token -- setup 30 pro
```

This creates:

```text
auth-keys/subscription-private.key  # issuer secret; never give it to clients
auth-keys/subscription-public.key   # loaded by the server
subscription.token                 # loaded by the client
```

### 3. Start the server

TUN creation may require elevated privileges:

```bash
sudo ./target/debug/payphone-server --help
sudo ./target/debug/payphone-server --bind 0.0.0.0:40404
```

The server:

- listens on `127.0.0.1:40404`;
- creates `dev-certs/payphone-cert.der` and `dev-certs/payphone-key.der` when needed;
- creates the server TUN interface at `10.77.0.1/24`;
- loads `auth-keys/subscription-public.key` with key ID `1`.

### 4. Start the client

In another terminal:

```bash
sudo ./target/debug/payphone-client --help
sudo ./target/debug/payphone-client --server 127.0.0.1:40404
```

Flags override `.env` and an optional `payphone.toml` (`server`, `psk`, `sni`, `tls_pin`, `token`, ...). The PSK can stay in the environment.

The client reads `subscription.token`, authenticates, receives an address beginning with `10.77.0.2`, creates its TUN interface, and starts forwarding packets. From a third terminal, try:

```bash
ping 10.77.0.1
```

Press `Ctrl+C` to stop either process.

### 5. Test session resumption

Stop only the client and start it again while the server remains running (or after a server restart, within five minutes):

```bash
sudo ./target/debug/payphone-client
```

The client stores an encrypted session ID/resume-token pair in `.payphone-session` (ChaCha20-Poly1305, key derived from the obfuscation PSK). A leftover 48-byte plaintext file from older builds is still accepted once, then rewritten encrypted. If the session is still on disk on the server and the subscription has not expired, the server restores the same logical session and VPN address. Idle sessions expire after five minutes. `Ctrl+C` sends `Close` and drops the saved session on both sides.

To force a new authenticated handshake, delete `.payphone-session` before starting the client.

## Docker / remote deployment

The `Dockerfile` builds `server`, `client`, and `token` images from the same multi-stage build. Locally, `docker-compose.yml` runs server + client + a one-off token issuer together.

For a **remote server deployment** (e.g. behind a PaaS like Coolify), use `docker-compose.server.yml` instead of a platform's generic "port mapping" UI/API field. Many such tools default to TCP-only port publishing and either reject a `/udp` suffix outright or silently drop it — `docker ps` then shows the port as merely *exposed*, not actually published (`40404/udp` instead of `0.0.0.0:40404->40404/udp`), and UDP datagrams die at the host's network interface with zero visibility into why. A native Compose `ports: - "40404:40404/udp"` entry doesn't have this problem. The same file also publishes `443/tcp` → container `40443` for the HTTPS camouflage front. Set `PAYPHONE_BIND_ADDR`, `PAYPHONE_OBFS_PSK`, and `PAYPHONE_DEV_MODE` through the platform's own environment variable mechanism. Do not put PAYPHONE TCP/UDP 443 on a host that still has Traefik (or another proxy) bound to 443.

Because the default self-signed certificate lives on the `payphone-certs` volume, the client's pin stays valid across rebuilds. After the first deploy (or if you delete the volume), copy the leaf hex from the server log into `dev-certs/payphone-cert.der`:

```bash
echo <hex from server logs> | xxd -r -p > dev-certs/payphone-cert.der
```

If the VPS already has a DNS name, skip the pin. Set `PAYPHONE_TLS_DOMAIN=vpn.example.com` (and optionally `PAYPHONE_ACME_EMAIL`) on the server. Let's Encrypt talks TLS-ALPN-01 on the same TCP 443 as the landing page. The client:

```bash
sudo ./target/debug/payphone-client --server vpn.example.com:443
```

SNI becomes `vpn.example.com` and `--tls-ca system` is implied. Staging: `PAYPHONE_ACME_STAGING=true` (browsers and the client will not trust it unless you also pin). Mounted certbot PEMs still work via `PAYPHONE_TLS_CERT` / `PAYPHONE_TLS_KEY` and reload when the files change.

Set `PAYPHONE_DEV_MODE=true` on both sides to log every raw UDP datagram (size + sender) before obfuscation is attempted — useful when diagnosing whether packets are reaching the server at all versus being rejected after arrival. Leave it `false` (the default) otherwise: staying silent toward unrecognized traffic is part of the defense against DPI active-probing (see [Wire obfuscation](#wire-obfuscation)).

## Subscription token tool

Generate a key pair once:

```bash
cargo run -p payphone-token -- init
```

Issue a token using the existing private key:

```bash
cargo run -p payphone-token -- issue <days> <plan>
```

Generate missing keys and issue a token in one command:

```bash
cargo run -p payphone-token -- setup <days> <plan>
```

Revoke a token (append its `token_id` to `auth-keys/revoked-token-ids.txt`; the server re-reads the file on each auth, no restart):

```bash
cargo run -p payphone-token -- revoke subscription.token
# or a 32-char hex token_id
```

Point the server at the same file with `--revoke-file` / `PAYPHONE_REVOKE_FILE` (default `auth-keys/revoked-token-ids.txt`).

Available plans currently encode these claims:

| Plan | Device limit | Maximum Mbps |
| --- | ---: | ---: |
| `basic` | 1 | 100 |
| `pro` | 5 | 500 |
| `unlimited` | 255 | 0 (unlimited) |

Tokens are fixed-size 135-byte binary documents. Their signed claims include the key ID, token ID, client ID, issue/activation/expiry timestamps, plan, device limit, and bandwidth limit. The server enforces the device limit (oldest session is replaced) and the Mbps cap (inner IP packets over the limit are dropped).

## Wire obfuscation

Every UDP datagram sent by the client or server is wrapped in a lightweight
obfuscation layer (`payphone_transport::obfuscation`) before it hits the
network, and unwrapped on receive:

```text
[ 8-byte random salt ][ XOR(tiled SHA256(shared secret || salt),
                             [2-byte length][real payload][random padding]) ]
```

This is not encryption — QUIC's own TLS 1.3 already provides
confidentiality and integrity. Its only job is to stop PAYPHONE datagrams
from looking like QUIC on the wire, since QUIC's handshake has a
recognizable byte signature (long header form, version field) regardless
of port. This matters because some DPI middleboxes not only match that
signature passively, but actively probe suspected VPN endpoints — dialing
the IP:port themselves and completing a QUIC handshake to confirm and
blocklist it. A datagram that doesn't decode with the shared secret is
silently dropped before it ever reaches the QUIC layer, so a probe that
doesn't know the secret gets no response at all.

The wire length is rounded up to one of a handful of fixed buckets (see
`PADDING_BUCKETS` in `obfuscation.rs`) instead of exactly tracking the real
QUIC datagram size, and the client's keepalive `PING` fires at a jittered
interval instead of a fixed one — both aimed at the traffic-shape signals
below, not at the byte-level signature.

Both sides must be configured with the same secret via `PAYPHONE_OBFS_PSK`
(see `.env.example`). There is no built-in default — the process refuses
to start without it, and refuses to start with the literal placeholder
value from `.env.example` or anything under 16 characters, since a secret
compiled into open-source code (or left as the documented placeholder)
provides no real protection against an adversary who can read the source.

### What this does *not* hide

Obfuscation defeats passive QUIC-signature matching and blind active
probing. It does **not** make a PAYPHONE connection indistinguishable from
ordinary traffic under traffic-shape analysis — a DPI system like Russia's
TSPU doesn't need to identify the protocol by name to block it, only to
classify the flow as "probably a VPN tunnel":

- **Fixed, non-standard port.** A sustained encrypted UDP flow to
  `40404` is itself a signal — nothing legitimate commonly runs there.
- **Packet-length clustering.** Even with bucketed padding, QUIC's own
  packetization still produces a fairly small set of recurring sizes
  (handshake/MTU-probe near the MTU ceiling, small ACK-only packets,
  etc.) — real HTTP/3 traffic from major CDNs has its own, different
  size distribution that this project doesn't currently mimic.
- **One long-lived flow.** Full-tunnel routing means all of a client's
  traffic rides one UDP 4-tuple for the session's duration — a classic
  VPN traffic shape regardless of what the bytes look like.
- **Selective silence.** A server that answers only holders of the
  shared secret and stays silent to everyone else is itself a
  distinguishing behavior (a public HTTP/3 server responds to anyone).
- **No authentication in the obfuscation layer.** A wrong-secret
  datagram of ordinary length still gets XOR'd into *something* and
  handed to `quinn`, which discards it as malformed QUIC — functionally
  fine, but the obfuscation layer itself can't distinguish "wrong
  secret" from "valid but unparseable," only QUIC's own parsing can.

Getting past this class of detection reliably needs a different transport
model — tunneling inside TLS on port 443 that looks like a real website
to scanners. PAYPHONE can do that with optional REALITY (below).

PAYPHONE already speaks **two** transports on the same host:

- **UDP 443** — obfuscated QUIC (the default client path).
- **TCP 443** — ordinary TLS 1.3 with ALPN `http/1.1`. A browser or
  probe that `GET`s the port receives a small landing page. A PAYPHONE
  client (`PAYPHONE_TRANSPORT=tls`) sends protocol frames on that same
  TLS stream after the handshake.

That is camouflage for "is anything listening on 443?", not a clone of
Cloudflare's certificate/JA3.

Optional **REALITY** on TCP 443 (`PAYPHONE_REALITY=on`, default **off**):

- **B (outer):** Xray-compatible ClientHello `session_id` auth (X25519 +
  HKDF-SHA256 `"REALITY"` + AES-256-GCM). A probe that fails that check is
  TCP-spliced to `PAYPHONE_REALITY_DEST` (a real TLS 1.3 site reachable
  from the VPS).
- **A (inner):** a ClientHello that authenticates gets an ephemeral Ed25519
  certificate signed with HMAC-SHA512(AuthKey, pubkey) — Xray's
  `VerifyPeerCertificate` check. Then PAYPHONE frames, not VLESS.
  An Xray/v2ray client can pass the outer handshake only if keys match; it
  still will not get a VPN (wrong inner protocol).
- **ClientHello:** Chrome 131-shaped (GREASE, shuffled extensions, ALPN `h2`
  + `http/1.1`, GREASE ECH, X25519MLKEM768 + X25519). The hybrid share carries
  a real FIPS 203 ML-KEM-768 public key; the VPN still completes with X25519.
  The TLS stack is custom so CertificateVerify can still be Ed25519 HMAC even
  though Chrome does not advertise `ed25519` in `signature_algorithms`.
- **ServerHello (JA3S):** after auth the server dials dest with the same
  ClientHello, copies dest's ServerHello, and overwrites only the X25519
  `key_share` (Xray's rewrite). Cipher and extension order stay dest's, so
  JA3S matches. AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305 are all
  spoken. If dest is down, PAYPHONE falls back to its own ServerHello.
- **Encrypted tail:** dest record sizes after ServerHello are copied the way
  Xray does. If dest puts EncryptedExtensions+Certificate+… in one TLS record
  larger than 512 bytes (Chrome/Google), PAYPHONE pads that one record. If dest
  splits the flight (small EE, then Cert, … — `www.microsoft.com`), each of
  EE / Cert / CertificateVerify / Finished is its own padded record. Dummy
  NewSessionTicket-sized records follow Finished when dest sent extras in the
  first flight. After ClientFinished, PAYPHONE also emits dest's **post-handshake**
  `0x17` sizes (second ticket, etc.) learned from three background dest probes
  (ALPN none / `http/1.1` / `h2`, Xray `GlobalPostHandshakeRecordsLens`). The
  authenticated ClientHello picks the matching bucket.
- **EncryptedExtensions content** is inside TLS 1.3 AEAD, so dest plaintext is
  not visible on the wire. PAYPHONE echoes the client's ALPN (`h2` if offered).
  Record *sizes* still follow dest.
- **Not VLESS/Vision.** Inner frames stay PAYPHONE. Matching Xray REALITY keys
  only gets you past the outer handshake.

TLS 1.3 encrypts the certificate, so probes never see the HMAC leaf. The REALITY client
verifies HMAC and does not need `--tls-pin`. Send dest's hostname as SNI
(`--reality-sni`). QUIC/UDP is unchanged; REALITY is `PAYPHONE_TRANSPORT=tls`
only.

```bash
cargo run -p payphone-token -- reality-init
# server: PAYPHONE_REALITY=on PAYPHONE_REALITY_DEST=www.microsoft.com:443
#         PAYPHONE_REALITY_PRIVATE_KEY=... PAYPHONE_REALITY_SHORT_ID=...
# client: --transport tls --reality-pubkey ... --reality-short-id ... --reality-sni www.microsoft.com
```

Do not enable REALITY in Coolify until dest + keys are set. `payphone-token reality-init` writes `auth-keys/reality-private.key`, `reality-public.key`, and `reality-short-id.txt`. Then `PAYPHONE_REALITY=on` plus `PAYPHONE_REALITY_DEST`. If `PAYPHONE_TLS_DOMAIN` is also set, a browser that hits **that name** still gets your landing page (and ACME still works). Other ClientHellos splice to dest — so 443 does not lose the site for your own hostname.

The TCP path does not use UDP obfuscation.

## Protocol overview

Every PAYPHONE message is carried in a QUIC datagram (default) or as a
length-prefixed TLS byte stream (`PAYPHONE_TRANSPORT=tls`). Both start
with a 16-byte header:

| Field | Size |
| --- | ---: |
| Protocol version | 1 byte |
| Frame type | 1 byte |
| Flags | 2 bytes |
| Payload length | 4 bytes |
| Sequence number | 8 bytes |

Multi-byte integers use network byte order. Protocol version 1 supports these frame types:

| Value | Frame | Direction | Purpose |
| ---: | --- | --- | --- |
| 1 | `Data` | Both | Carries a session ID, packet ID, and IP packet |
| 2 | `WhatsUpDude` | Client to server | Starts a session and includes the subscription token |
| 3 | `AllGoodDude` | Server to client | Accepts a session and assigns its address and resume secret |
| 4 | `Ping` | Client to server | Keepalive request |
| 5 | `Pong` | Server to client | Keepalive response |
| 6 | `Rekey` | Both | Rotates the resume token; 16-byte request or 48-byte nonce |
| 7 | `Close` | Both | Ends the session and frees its VPN address |
| 8 | `BackAgainDude` | Client to server | Requests session resumption |
| 9 | `StillGoodDude` | Server to client | Confirms session resumption |
| 10 | `AccessDeniedDude` | Server to client | Reports token or subscription rejection |

The maximum frame payload and maximum `DATA` payload are both 64 KiB. A handshake authentication token may be at most 2 KiB.

### Data path

```text
Application / kernel
        |
        v
   Client TUN  ->  DATA frame  ->  QUIC + TLS 1.3  ->  Server TUN
   Client TUN  <-  DATA frame  <-  QUIC + TLS 1.3  <-  Server TUN
```

The server maps destination VPN addresses to active sessions. Client-originated IPv4 packets are accepted only when their source address matches the address assigned to that session.

## Testing

Run the complete suite with:

```bash
cargo test --workspace
```

The workspace currently contains unit tests covering frames, protocol messages, subscription authentication, session persistence, device and bandwidth limits, IPv4 parsing, TLS identity creation, and QUIC endpoint binding. The endpoint test must be allowed to open a local UDP socket.

Formatting can be checked with:

```bash
cargo fmt --all -- --check
```

## Current limitations

- Only IPv4 packets are routed; IPv6 and roaming are advertised by the client but not negotiated by the server.
- The server runs a UDP DNS stub on `10.77.0.1:53` and the client pins that address, so DNS fails closed if the tunnel drops instead of leaking to the ISP. Browser DoH still bypasses the stub but rides the tunnel.
- Full-tunnel routing (`payphone_tun::routing`) is implemented for macOS, Linux, and Windows. Windows needs `wintun.dll` and an elevated process. IPv6 is blackholed on all three (`::/1` + `8000::/1`) so browsers fall back to IPv4 in the tunnel; there is still no in-tunnel IPv6. `--kill-switch` (default off) blackholes IPv4 too while the client is running if the tunnel is down. On-link LAN (printers, `192.168.x`) is not blocked. Windows also installs a catch-all NRPT rule so DNS is not still answered by the LAN resolver.
- Token revocations live in `PAYPHONE_REVOKE_FILE` (hex `token_id` per line). That is not a distributed store.
- Session sequence numbers reject frames more than 1024 behind the highest seen (reorder window). Exact duplicates inside that window still pass; QUIC/TLS already bind the datagram.
- REALITY (optional, TCP only) splices probes to dest and authenticates PAYPHONE clients with Xray's session_id scheme plus an HMAC-SHA512 Ed25519 leaf. ClientHello follows uTLS `HelloChrome_131` (GREASE pinned first/last, shuffled middle, GREASE ECH, real ML-KEM-768 + X25519) — not bit-identical to a live Chrome capture, and Chrome itself drifts every month. Authenticated ServerHello copies dest's JA3S and patches only the X25519 key_share. Dest encrypted handshake and post-handshake record sizes are padded (three ALPN probe classes). Inner protocol is PAYPHONE, not VLESS.

## Security notice

The default TLS identity is still self-signed with SNI `localhost`; the client pins `dev-certs/payphone-cert.der`. For a public name, set `PAYPHONE_TLS_DOMAIN` on the server (Let's Encrypt) or load PEM with `--tls-cert` / `--tls-key`. The client trusts public CAs when SNI looks like a real DNS name. The resume file is encrypted with a key derived from `PAYPHONE_OBFS_PSK`. Keep `auth-keys/subscription-private.key` secret.
