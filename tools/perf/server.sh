#!/bin/sh
set -eu
peer=$(getent ahostsv4 peer | awk 'NR==1 {print $1}')
test -n "$peer"
ip route add 198.18.0.2/32 via "$peer"
exec payphone-server
