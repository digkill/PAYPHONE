#!/usr/bin/env bash
# Deliberately damage only the disposable client's network namespace.
set -euo pipefail
client="$1"
results="$2"
server_ip="$(docker exec "$client" getent ahostsv4 server | awk 'NR == 1 {print $1}')"
[[ -n "$server_ip" ]] || { echo 'cannot resolve lab server' >&2; exit 1; }
for family_prefix in "4 0.0.0.0/1" "4 128.0.0.0/1" "4 $server_ip/32" "6 ::/1" "6 8000::/1"; do
  read -r family prefix <<< "$family_prefix"
  docker exec "$client" ip "-$family" route del "$prefix"
  restored=0
  for _ in {1..20}; do
    if [[ -n "$(docker exec "$client" ip "-$family" route show exact "$prefix")" ]]; then restored=1; break; fi
    sleep 0.1
  done
  [[ "$restored" == 1 ]] || { echo "watchdog did not restore $prefix" >&2; exit 1; }
done
docker exec "$client" ip -4 route > "$results/routes-after-repair-v4.txt"
docker exec "$client" ip -6 route > "$results/routes-after-repair-v6.txt"
docker exec "$client" ping -c 3 -W 2 10.77.0.1 > "$results/ping-after-repair.txt"
echo 'PASS: watchdog restored both IPv4 tunnel routes, server bypass and IPv6 blackholes'
