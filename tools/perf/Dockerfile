ARG BUILDER_IMAGE=payphone-perf-builder:local
ARG DEBIAN_IMAGE=public.ecr.aws/docker/library/debian:bookworm-slim
FROM ${BUILDER_IMAGE} AS binaries
FROM ${DEBIAN_IMAGE}
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       iperf3 iproute2 iputils-ping iptables ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=binaries /build/target/release/payphone-server /usr/local/bin/
COPY --from=binaries /build/target/release/payphone-client /usr/local/bin/
COPY --from=binaries /build/target/release/payphone-token /usr/local/bin/
COPY --chmod=755 tools/perf/server.sh /usr/local/bin/payphone-perf-server
