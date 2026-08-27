# =============================================================
# BUILDER
# =============================================================
FROM rust:slim-bookworm AS builder

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY payphone-core ./payphone-core
COPY payphone-auth ./payphone-auth
COPY payphone-transport ./payphone-transport
COPY payphone-tun ./payphone-tun
COPY payphone-client ./payphone-client
COPY payphone-server ./payphone-server
COPY payphone-token ./payphone-token

RUN cargo build --release \
    -p payphone-server \
    -p payphone-client \
    -p payphone-token

# =============================================================
# SERVER
# =============================================================
FROM debian:bookworm-slim AS server

# iptables: sets up NAT/MASQUERADE for the tunnel subnet so
# clients get real internet access, not just reach the server.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/target/release/payphone-server /usr/local/bin/payphone-server

# Verify-only key: safe to bake into the image. The private signing
# key never enters any container image.
COPY auth-keys/subscription-public.key ./auth-keys/subscription-public.key

EXPOSE 40404/udp

ENTRYPOINT ["/usr/local/bin/payphone-server"]

# =============================================================
# CLIENT
# =============================================================
FROM debian:bookworm-slim AS client

WORKDIR /app

COPY --from=builder /build/target/release/payphone-client /usr/local/bin/payphone-client

ENTRYPOINT ["/usr/local/bin/payphone-client"]

# =============================================================
# TOKEN (subscription key / token issuer helper)
# =============================================================
FROM debian:bookworm-slim AS token

WORKDIR /app

COPY --from=builder /build/target/release/payphone-token /usr/local/bin/payphone-token

ENTRYPOINT ["/usr/local/bin/payphone-token"]
