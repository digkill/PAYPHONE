# AGENTS

PAYPHONE is an experimental IPv4 VPN in this Rust workspace (v0.2.0). Read project memory before changing protocol, transport, routing, or auth.

Portfolio / agent workspace: **[`AgentDevelop/`](AgentDevelop/README.md)** (synced by Composer).

**Memory (source of truth for agents):** [`.cursor/memory/README.md`](.cursor/memory/README.md)

Always load:

- [`.cursor/memory/overview.md`](.cursor/memory/overview.md)
- [`.cursor/memory/conventions.md`](.cursor/memory/conventions.md)

Then only the topic you need: `architecture.md`, `protocol.md`, `transport.md`, `auth.md`, `routing.md`, `config.md`, `gotchas.md`.

Human docs: `README.md`, `docs/habr-payphone.md`. If they disagree with code, **code wins**. Update memory in the same change when you alter an invariant.

## Non-negotiables

- IP rides **QUIC datagrams**, not streams. Hot path: `send_vpn_datagram` / `send_datagram`, never `send_datagram_wait`.
- TUN start MTU is **1100** (frame overhead 40). Do not set 1280 “because IPv6”.
- UDP obfuscation padding is **0–32 bytes**, no size buckets (they break Quinn PMTU).
- Inner protocol is PAYPHONE frames, **not VLESS**. REALITY stays optional and default-off.
- Do not put `subscription-private.key` in images. Do not commit `.env`, tokens, or certs.
- `PAYPHONE_OBFS_PSK` is required, ≥16 chars, not the `.env.example` placeholder.
- macOS: never use `networksetup` to fix IPv6/DNS. Tear down routes **before** `wait_idle` on SIGINT.

## Workspace

`payphone-core` (wire) · `payphone-auth` / `payphone-token` (Ed25519 subscription) · `payphone-transport` (QUIC, obfuscation, TLS, REALITY) · `payphone-tun` (TUN + OS routes) · `payphone-server` / `payphone-client`.

```bash
cargo test --workspace
cargo fmt --all -- --check
```

Commands from repo root. Runtime paths are relative to CWD.
