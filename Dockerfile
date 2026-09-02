# Coolify runs `docker compose build --pull` on every deploy. Bare
# `rust:` / `debian:` names hit Docker Hub, and a shared VPS IP hits
# the anonymous 429 quickly. Public ECR is the same official images
# without that Hub quota.
ARG RUST_IMAGE=public.ecr.aws/docker/library/rust:slim-bookworm
ARG DEBIAN_IMAGE=public.ecr.aws/docker/library/debian:bookworm-slim

# =============================================================
# BUILDER
# =============================================================
FROM ${RUST_IMAGE} AS builder

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
FROM ${DEBIAN_IMAGE} AS server

# iptables: sets up NAT/MASQUERADE for the tunnel subnet so
# clients get real internet access, not just reach the server.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN mkdir -p /app/state

COPY --from=builder /build/target/release/payphone-server /usr/local/bin/payphone-server

# Verify-only key: safe to bake into the image. The private signing
# key never enters any container image.
COPY auth-keys/subscription-public.key ./auth-keys/subscription-public.key

EXPOSE 40404/udp
EXPOSE 40443/tcp

ENTRYPOINT ["/usr/local/bin/payphone-server"]

# =============================================================
# CLIENT
# =============================================================
FROM ${DEBIAN_IMAGE} AS client

WORKDIR /app

COPY --from=builder /build/target/release/payphone-client /usr/local/bin/payphone-client

ENTRYPOINT ["/usr/local/bin/payphone-client"]

# =============================================================
# TOKEN (subscription key / token issuer helper)
# =============================================================
FROM ${DEBIAN_IMAGE} AS token

WORKDIR /app

COPY --from=builder /build/target/release/payphone-token /usr/local/bin/payphone-token

ENTRYPOINT ["/usr/local/bin/payphone-token"]
