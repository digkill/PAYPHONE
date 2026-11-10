#!/usr/bin/env bash
# client-net owns the namespace, so Docker cannot remove eth0 when the VPN exits.
set -euo pipefail
client="$1"
observer="$2"
results="$3"
server_ip="$(docker exec "$client" getent ahostsv4 server | awk 'NR == 1 {print $1}')"
[[ -n "$server_ip" ]] || { echo 'cannot resolve lab server' >&2; exit 1; }
docker kill --signal SIGINT "$client" > /dev/null
stopped=0
for _ in {1..40}; do
  if [[ "$(docker inspect -f '{{.State.Running}}' "$client")" == false ]]; then stopped=1; break; fi
  sleep 0.25
done
[[ "$stopped" == 1 ]] || { echo 'client did not stop after SIGINT' >&2; exit 1; }
[[ "$(docker inspect -f '{{.State.ExitCode}}' "$client")" == 0 ]] || { echo 'client exited unsuccessfully' >&2; exit 1; }
docker exec "$observer" ip -4 route > "$results/routes-after-sigint-v4.txt"
docker exec "$observer" ip -6 route > "$results/routes-after-sigint-v6.txt"
for prefix in 0.0.0.0/1 128.0.0.0/1 "$server_ip/32"; do
  [[ -z "$(docker exec "$observer" ip -4 route show exact "$prefix")" ]] \
    || { echo "route remained after SIGINT: $prefix" >&2; exit 1; }
done
for prefix in ::/1 8000::/1; do
  [[ -z "$(docker exec "$observer" ip -6 route show exact "$prefix")" ]] \
    || { echo "route remained after SIGINT: $prefix" >&2; exit 1; }
done
docker exec "$observer" ip -4 route get 1.1.1.1 > "$results/default-after-sigint.txt"
echo 'PASS: SIGINT removed tunnel routes, server bypass and IPv6 blackholes'
