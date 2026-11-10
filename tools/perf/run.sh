#!/usr/bin/env bash
# Real TUN/NAT test confined to Docker network namespaces. No host route changes.
set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$repo"
seconds="${1:-30}"
rate="${2:-300M}"
delay="${LAB_DELAY_MS:-0}"
streams="${LAB_TCP_STREAMS:-1}"
warmup="${LAB_WARMUP_SECONDS:-3}"
tcp_only="${LAB_TCP_ONLY:-0}"
udp_seconds="${LAB_UDP_SECONDS:-$seconds}"
udp_warmup="${LAB_UDP_WARMUP_SECONDS:-$warmup}"
[[ "$seconds" =~ ^[1-9][0-9]*$ ]] || { echo "duration must be positive seconds" >&2; exit 1; }
[[ "$rate" =~ ^[1-9][0-9]*[KMG]?$ ]] || { echo "rate must be an iperf bitrate, e.g. 300M" >&2; exit 1; }
[[ "$delay" =~ ^[0-9]{1,3}$ ]] || { echo "LAB_DELAY_MS must be 0..999" >&2; exit 1; }
[[ "$streams" =~ ^[1-9][0-9]?$ ]] && ((streams <= 64)) || { echo "LAB_TCP_STREAMS must be 1..64" >&2; exit 1; }
[[ "$warmup" =~ ^(0|[1-9][0-9]{0,2})$ ]] && ((warmup <= 300)) || { echo "LAB_WARMUP_SECONDS must be 0..300" >&2; exit 1; }
[[ "$tcp_only" == 0 || "$tcp_only" == 1 ]] || { echo "LAB_TCP_ONLY must be 0 or 1" >&2; exit 1; }
[[ "$udp_seconds" =~ ^[1-9][0-9]*$ ]] || { echo "LAB_UDP_SECONDS must be positive seconds" >&2; exit 1; }
[[ "$udp_warmup" =~ ^(0|[1-9][0-9]{0,2})$ ]] && ((udp_warmup <= 300)) || { echo "LAB_UDP_WARMUP_SECONDS must be 0..300" >&2; exit 1; }
tcp_rate="$(python3 - "$rate" "$streams" <<'PY'
import sys
rate = sys.argv[1]
factor = {"K": 1000, "M": 1000000, "G": 1000000000}.get(rate[-1], 1)
total = int(rate[:-1] if factor != 1 else rate) * factor
per_stream = total // int(sys.argv[2])
if per_stream < 1:
    raise SystemExit("bitrate must be at least the TCP stream count")
print(per_stream)
PY
)"
mkdir -p runtime
state="$(mktemp -d "$repo/runtime/perf-lab.XXXXXX")"
chmod 700 "$state"
mkdir -p "$state/issuer" "$state/server" "$state/client" "$state/results"
project="payphone-perf-$$"
builder="payphone-perf-builder:local"
image="payphone-perf-lab:local"
umask 077
{
  echo "LAB_STATE=$state"
  echo "LAB_IMAGE=$image"
  echo "PAYPHONE_OBFS_PSK=$(openssl rand -hex 32)"
} > "$state/lab.env"
compose=(docker compose --env-file "$state/lab.env" -p "$project" -f tools/perf/compose.yml)
cleanup() {
  "${compose[@]}" logs --no-color > "$state/services.log" 2>&1 || true
  "${compose[@]}" down --remove-orphans > "$state/cleanup.log" 2>&1 || true
}
trap cleanup EXIT
echo "Lab results: $state/results"
if [[ "${PAYPHONE_PERF_SKIP_BUILD:-0}" != 1 ]]; then
  docker build --target builder --build-arg "RUST_IMAGE=${PAYPHONE_PERF_RUST_IMAGE:-public.ecr.aws/docker/library/rust:slim-bookworm}" -t "$builder" .
  docker build --build-arg "BUILDER_IMAGE=$builder" \
    --build-arg "DEBIAN_IMAGE=${PAYPHONE_PERF_DEBIAN_IMAGE:-public.ecr.aws/docker/library/debian:bookworm-slim}" \
    -t "$image" -f tools/perf/Dockerfile .
fi
docker run --rm -v "$state/issuer:/lab" -w /lab "$image" \
  payphone-token setup 1 unlimited > "$state/issuer.log" 2>&1
cp "$state/issuer/auth-keys/subscription-public.key" "$state/server/subscription-public.key"
cp "$state/issuer/subscription.token" "$state/client/subscription.token"
"${compose[@]}" up -d peer server
ready=0
for _ in {1..60}; do
  if "${compose[@]}" exec -T server sh -c 'test -s /lab/dev-certs/payphone-cert.der && ip link show payphone0 >/dev/null' 2>/dev/null; then ready=1; break; fi
  sleep 0.5
done
[[ "$ready" == 1 ]] || { echo "server did not become ready; see $state/services.log" >&2; exit 1; }
cp "$state/server/dev-certs/payphone-cert.der" "$state/client/payphone-cert.der"
"${compose[@]}" up -d client-net
if [[ "$delay" != 0 ]]; then
  # Shape the path before the handshake, so its initial RTT sample is valid.
  for service in client-net server; do
    # Delay the outer VPN link. NAT traffic to the local peer stays on its
    # own immediate queue; delaying it too would emulate a second WAN leg.
    "${compose[@]}" exec -T "$service" tc qdisc replace dev eth0 root handle 1: prio bands 3 priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
    "${compose[@]}" exec -T "$service" tc qdisc replace dev eth0 parent 1:1 handle 10: pfifo limit 8192
    "${compose[@]}" exec -T "$service" tc qdisc replace dev eth0 parent 1:2 handle 20: pfifo limit 8192
    "${compose[@]}" exec -T "$service" tc qdisc replace dev eth0 parent 1:3 handle 30: netem delay "${delay}ms" limit 8192
    port_match=dport
    if [[ "$service" == server ]]; then port_match=sport; fi
    "${compose[@]}" exec -T "$service" tc filter add dev eth0 protocol ip parent 1: prio 1 u32 \
      match ip protocol 17 0xff match ip "$port_match" 40404 0xffff flowid 1:3
  done
fi
"${compose[@]}" up -d client
ready=0
for _ in {1..30}; do
  if "${compose[@]}" exec -T client ping -c 1 -W 1 10.77.0.1 > /dev/null 2>&1; then ready=1; break; fi
  sleep 0.5
done
[[ "$ready" == 1 ]] || { echo "client tunnel did not become ready; see $state/services.log" >&2; exit 1; }
bash tools/perf/verify-repair.sh "$("${compose[@]}" ps -q client)" "$state/results"
snapshot() {
  local label="$1"
  for service in client server peer; do
    "${compose[@]}" exec -T "$service" ip -s link > "$state/results/$label-$service-links.txt"
    "${compose[@]}" exec -T "$service" ss -uanmp > "$state/results/$label-$service-sockets.txt"
    "${compose[@]}" exec -T "$service" tc -s qdisc show dev eth0 > "$state/results/$label-$service-qdisc.txt"
    "${compose[@]}" exec -T "$service" cat /proc/net/snmp > "$state/results/$label-$service-snmp.txt"
  done
}
"${compose[@]}" exec -T client ip route add 198.18.0.2/32 via 10.77.0.1 dev payphone0
"${compose[@]}" exec -T client ip route get 198.18.0.2 > "$state/results/route.txt"
printf 'duration=%s\nrate=%s\negress_delay_ms=%s\nworkers=%s\n' \
  "$seconds" "$rate" "$delay" "${LAB_TOKIO_WORKERS:-2}" > "$state/results/parameters.txt"
printf 'tcp_streams=%s\ntcp_bits_per_second_per_stream=%s\n' \
  "$streams" "$tcp_rate" >> "$state/results/parameters.txt"
printf 'warmup_seconds=%s\ndelay_scope=outer_quic_udp_only\n' "$warmup" >> "$state/results/parameters.txt"
printf 'tcp_only=%s\n' "$tcp_only" >> "$state/results/parameters.txt"
printf 'udp_seconds=%s\nudp_warmup_seconds=%s\n' "$udp_seconds" "$udp_warmup" >> "$state/results/parameters.txt"
docker image inspect -f '{{.Id}}' "$image" > "$state/results/image-id.txt"
for service in client server; do
  "${compose[@]}" exec -T "$service" sha256sum "/usr/local/bin/payphone-$service" > "$state/results/$service-sha256.txt"
done
"${compose[@]}" exec -T client ping -c 3 -W 2 10.77.0.1 > "$state/results/ping-vpn-server.txt"
"${compose[@]}" exec -T client ping -c 3 -W 1 198.18.0.2 > "$state/results/ping-idle.txt"
"${compose[@]}" exec -T client iperf3 --version > "$state/results/iperf-version.txt"
snapshot before
echo "TCP bidirectional: $rate total per direction, $streams streams, $seconds measured seconds"
"${compose[@]}" exec -T client ping -i 0.2 -c "$(((seconds + warmup) * 5))" -W 1 198.18.0.2 \
  > "$state/results/ping-loaded.txt" &
ping_job=$!
"${compose[@]}" exec -T client iperf3 -c 198.18.0.2 --bidir -P "$streams" -b "$tcp_rate" -w 4M -O "$warmup" -t "$seconds" --get-server-output -J \
  > "$state/results/tcp-bidir.json"
wait "$ping_job" || true
snapshot after-tcp
if [[ "$tcp_only" == 1 ]]; then
  "${compose[@]}" exec -T server iptables -t nat -nvL POSTROUTING > "$state/results/nat.txt"
  bash tools/perf/verify-teardown.sh "$("${compose[@]}" ps -q client)" \
    "$("${compose[@]}" ps -q client-net)" "$state/results"
  python3 tools/perf/report.py "$state/results" --tcp-only
  exit
fi
echo "UDP upload: $rate, 1000-byte datagrams, $udp_seconds measured seconds"
"${compose[@]}" exec -T client iperf3 -c 198.18.0.2 -u -b "$rate" -w 4M -l 1000 -O "$udp_warmup" -t "$udp_seconds" --get-server-output -J \
  > "$state/results/udp-upload.json"
snapshot after-upload
echo "UDP download: $rate, 1000-byte datagrams, $udp_seconds measured seconds"
"${compose[@]}" exec -T client iperf3 -c 198.18.0.2 -u -R -b "$rate" -w 4M -l 1000 -O "$udp_warmup" -t "$udp_seconds" --get-server-output -J \
  > "$state/results/udp-download.json"
snapshot after-download
"${compose[@]}" exec -T server iptables -t nat -nvL POSTROUTING > "$state/results/nat.txt"
bash tools/perf/verify-teardown.sh "$("${compose[@]}" ps -q client)" \
  "$("${compose[@]}" ps -q client-net)" "$state/results"
python3 tools/perf/report.py "$state/results"
