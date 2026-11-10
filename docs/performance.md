# Performance validation

The target is **200–300 Mbps aggregate inside one VPN session**. Multiple TCP
flows may share that session. A single TCP download is a separate measurement.
Tests below exercise simultaneous upload and download through QUIC DATAGRAM,
real Linux TUN interfaces and server NAT.

These are controlled local measurements with an emulated VPN-link delay.
Production VPS capacity, real WAN behavior and physical phone throughput still
need measurement on the intended devices and route.

## Changes

- `send_vpn_datagram` acquires the Quinn connection lock once. Normal DATA tries
  enqueue first; oversized sends consult the budget and use IPv4 fragmentation
  or ICMP feedback. IP remains on DATAGRAM, without `send_datagram_wait`.
- Frame + DATA encode directly in one allocation/copy. UDP transmit storage is
  reused; receive obfuscation decrypts and compacts in place. Padding remains
  random 0–32 bytes and the wire format remains compatible.
- Mixed GRO plaintext lengths preserve **every** datagram and their order.
  Equal wire sizes can hide different plaintext sizes because padding varies.
  The previous fallback discarded everything after the first datagram. The new
  bounded queue retains at most one kernel receive batch, using shared Bytes
  slices; normal uniform GRO needs no per-packet allocation. Tests cover mixed
  batches, a short middle segment, subsequent iovecs and partial queue draining.
- BBR with the local startup-window correction and GSO are enabled. ACK feedback is requested every two ack-eliciting
  packets with a 1 ms maximum delay. Packet reordering tolerance is 2048;
  time-based loss detection remains enabled with a 2.0 RTT multiplier. DATAGRAM send/receive queues
  are bounded at 16 MiB each per connection and allocated as traffic queues.
- The local quinn-proto 0.11.19 patch expands authenticated packet replay
  tracking from 129 to 2048 packet numbers. A 256-byte ring retains duplicate
  rejection without shifting the entire window per packet. The server PAYPHONE
  sequence tolerance is 65536, covering multiple DATA frames per QUIC packet.
  Opt-in `dup_discard` counts replay-filter discards; a real encrypted-duplicate
  regression checks that a replay is counted and delivered only once. Source,
  licenses and exact patch: [vendor notes](../vendor/quinn-proto/PATCHES.md).
- QUIC packet MTU stays at 1200 until discovery accounts for the obfuscation
  wrapper's additional 10–42 bytes. A probe with short padding otherwise does
  not establish safety for a later long pad. TUN starts at **1100**, then follows
  the actual DATAGRAM budget (1122 in this lab). Linux uses the native MTU ioctl.
- Linux TUN TX queues hold at most 8192 packets, compared with the previous 500.
  This absorbs short bursts; it can increase queued latency under congestion.
  The queue is not allocated in advance or used as a bitrate guarantee.
- Route watchdog commands run on a blocking worker, with at most one outstanding
  job. Maintenance is synchronized with idempotent teardown; a retained worker
  Arc cannot reinstall routes after shutdown. On Linux it reads kernel IPv4/IPv6
  tables first and only replaces routes when required. Rewriting healthy routes
  every 400 ms produced intermittent throughput stalls. DNS pin maintenance
  stays enabled. Headless CLI rain is disabled.
- Android and Apple QUIC receive paths reuse one 65535-byte scratch buffer,
  serialize receives and copy only the actual frame.

## Reproduce the aggregate TCP acceptance check

```bash
cargo test --workspace
cargo fmt --all -- --check
CARGO_TARGET_DIR="$PWD/target" cargo test --manifest-path vendor/quinn-proto/Cargo.toml --lib
LAB_DELAY_MS=25 LAB_TCP_STREAMS=8 LAB_WARMUP_SECONDS=30 LAB_TCP_ONLY=1 \
  tools/perf/run.sh 120 300M
```

Eight TCP flows run **inside one VPN connection**, not eight VPN connections.
The script divides the total target by the flow count: at 300M each flow gets
37,500,000 bits/s per direction. It uses two Tokio workers per process by default.
Warmup is explicit and excluded from acceptance; cold-start convergence is not
covered by a steady-state result.

The report requires receiver averages and every valid full one-second receiver
window to reach 200 Mbps. It checks upload intervals from `--get-server-output`
as well as client-side download intervals. At least duration-minus-one full
windows are required for each direction. Warmup, partial tails and iperf3 3.12's
malformed `-O` transition are excluded; real zero-throughput full intervals fail.
A missing receiver, insufficient coverage or threshold failure returns nonzero.

For the full TCP + UDP suite, omit `LAB_TCP_ONLY=1`. UDP tests use 1000-byte
payloads and the full configured target; their additional acceptance limit is
0.1% receiver loss. TCP-only acceptance does not imply UDP passed that loss gate.
`LAB_TCP_STREAMS=1` tests a single TCP flow. Defaults: one flow, 3s warmup, no
added delay, full suite. Use `LAB_WARMUP_SECONDS=0` to inspect cold start.

Overrides: `PAYPHONE_PERF_MIN_MBPS`, `PAYPHONE_PERF_MAX_LOSS_PCT`,
`LAB_TOKIO_WORKERS`, `LAB_UDP_SECONDS` and `LAB_UDP_WARMUP_SECONDS`. Parser regressions can run without Docker:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tools/perf -p test_report.py
```

## Measurements (2026-11-06)

These results describe the historical CUBIC profile. The current BBR profile
with its startup correction was selected during the later WAN investigation
below; this table does not establish the same acceptance result for it.

Host: Apple M3 Max, 14 cores, Darwin 27 arm64. Lab: Docker LinuxKit arm64,
14 vCPUs / 8 GiB VM, iperf3 3.12, release binaries, unlimited test subscription,
self-signed certificate pin. Client and server each use two Tokio workers;
this is not a claim that a two-vCPU VPS has the same capacity.

The final delay profile adds 25 ms to **outer QUIC UDP only**, before handshake.
The nearby NAT peer's traffic uses an immediate queue. Measured idle peer ping
was about 54 ms. No random loss or link-rate cap was injected. `-w 4M` results in
8 MiB application socket buffers on this Linux kernel. Avoid builds and other
heavy work during measurement.

The unchanged-profile confirmation passed the complete acceptance report:
120s bidirectional TCP after 30s warmup, then 30s UDP in each direction after
3s warmup. Route repair and SIGINT teardown passed with the watchdog enabled.
Raw evidence: `runtime/perf-lab.sdjtv8/results/`.

| Test | Receiver average Mbps | Minimum full 1s Mbps | Full windows | UDP loss |
| --- | ---: | ---: | ---: | ---: |
| TCP upload, simultaneous | 300.04 | 273.67 | 119 | — |
| TCP download, simultaneous | 299.90 | 275.66 | 119 | — |
| UDP upload | 300.00 | 298.59 | 30 | 0% |
| UDP download | 300.00 | 270.50 | 29 | 0% |

Replay discards stayed at zero; QUIC transport loss counters reached 56/457
(client/server), while application UDP receiver loss was zero.
Loaded ping: 750/750 replies, average 58.98 ms, maximum 495.89 ms. These bursts
of latency remain a limitation even though throughput passed. The test has no
injected random loss or bandwidth bottleneck, and covers two measured minutes,
not day-long stability. Cold-start and real-server validation remain separate.

The previous run of this same profile (`runtime/perf-lab.Dkwbje/results/`)
averaged 300.04/299.90 Mbps, minimum accepted TCP windows 236.04/224.65 Mbps,
and UDP loss 0%. It **did not pass the complete report**: two download intervals
were 1.103/0.897s due to iperf timer slip, leaving 117 accepted windows (119
required). Their rates were 247.88/364.68 Mbps. The parser gate and code were
unchanged for confirmation; this incomplete-coverage run is retained as evidence.
Its loaded ping averaged 61.03 ms and peaked at 500.67 ms. Replay discards stayed
at zero; transport loss reached 184, while UDP receiver loss remained zero.

## Diagnostics and limits

Earlier 120-second delayed-path tests averaged approximately 300 Mbps in both
TCP directions but had one-second windows as low as 52/87 Mbps. Zero UDP socket
errors did not rule out internal drops: temporary tracing showed hundreds of
replay-filter discards. This led to the local Quinn window patch. Tracing tied
to an upstream source line was removed and replaced with the explicit counter.

The replay patch alone did not establish stability: a BBR run still had minimum
windows around 110/109 Mbps. After switching to CUBIC, a diagnostic run without
route rewrites delivered 300.30/300.20 Mbps for 120s, with minimum windows
256.89/257.40. The shipped change retains the watchdog and checks kernel tables
before writing them; acceptance must run with this protection enabled.

Before these fixes, a 30-second test passed aggregate TCP but failed the UDP
loss gate (0.1035% upload, limit 0.1%). That result is not a full acceptance pass.
Raw evidence: `runtime/perf-lab.MEdct1/results/`. The earlier long TCP failure is
`runtime/perf-lab.UaE2cy/results/`; replay-patch-only failure is
`runtime/perf-lab.59PJNP/results/`. The no-rewrite diagnostic is
`runtime/perf-lab.l9r6V8/results/`.

An earlier zero-added-delay 120s single-flow test delivered approximately
300 Mbps both ways, with minimum windows 245/245 Mbps. It demonstrates local
capacity, not a single-TCP-flow guarantee at higher RTT. Warmup, cold start,
packet loss and abrupt path changes need separate tests. A BBR experiment with
delay added after handshake collapsed to 1–2 Mbps; it does not describe the
shipped CUBIC profile and does not establish roaming support.

## Lab isolation and evidence

`tools/perf/run.sh` starts server, client, peer and a small `client-net` namespace
owner on a private Docker network. Only the peer owns `198.18.0.2`; the client
routes it through payphone0, then the server forwards and applies NAT. No host
routes or production VPN resources are changed and no iperf ports are published.
The delay qdiscs and filters live only in these network namespaces.

Before load, the lab deliberately deletes each of the five maintained routes
and verifies automatic repair and tunnel reachability. The observer verifies removal of split routes, server bypass and IPv6 blackholes
after SIGINT, then checks routing through the original default while eth0 still
exists. This exercises Linux route cleanup, not macOS DNS restoration.

Raw client/server JSON, parameters, binary SHA256, image ID, route/NAT evidence,
interface/socket/qdisc/SNMP snapshots and logs remain under ignored
`runtime/perf-lab.*`. Parent directories contain ephemeral test credentials;
share only the statistics under `results/`. Signing keys are bind-mounted for
issuance after image build and are never copied into images. Containers and the
private network are removed on exit. Docker needs `/dev/net/tun` and NET_ADMIN.

Normal builds use the repo Dockerfile builder plus `tools/perf/Dockerfile`.
ECR is the default image source; overrides are `PAYPHONE_PERF_RUST_IMAGE` and
`PAYPHONE_PERF_DEBIAN_IMAGE`. `PAYPHONE_PERF_SKIP_BUILD=1` reuses the lab image:
rebuild it after changing source. Registry TLS timed out in this session; a
cached public Rust bookworm builder and SHA256-checked official Debian packages
were used to create a local lab image instead.

`PAYPHONE_QUIC_STATS=1` enables opt-in RTT, cwnd, loss, replay-filter discards and DATAGRAM counters once
per second in Rust client/server, plus mixed-GRO diagnostics. Default is off.
It does not dump payload, PSK or subscription tokens; the lab enables it.

## Transport-only check

```bash
tools/perf/check-local.sh 120 300
```

This loopback benchmark creates a fresh DATA frame per 1100-byte payload and
runs upload/download together. It reports source/receiver windows, queues, RTT,
loss and delivery after a 500 ms drain. It creates no TUN and changes no routes.
It excludes authentication, TUN, NAT, WAN and mobile bindings. Tokio defaults
apply unless `TOKIO_WORKER_THREADS` is set. `PAYPHONE_BENCH_REUSE_FRAME=1` selects
the older template-only diagnostic. A raw transport result is not a VPS claim.

## Dependency regression and deployment follow-up

Quinn requires at least 0.11.12; the lockfile uses quinn-proto 0.11.19 and
quinn-udp 0.5.16. The outgoing-queue regression enqueues 100,000 datagrams without
draining, exercising the eviction accounting that previously panicked.
See the [upstream fix](https://github.com/quinn-rs/quinn/issues/2805).

Repeat on the intended client/server and a controlled host beyond NAT for at
least 10–15 minutes. Record CPU/RSS, NIC rate, actual socket buffers, unloaded
and loaded RTT, loss, warmup and per-second rates. Test cold start and abrupt
path changes separately. A 65,533-address pool is an address limit; concurrency
requires separate fairness and resource testing.

On physical Android/iPhone, validate QUIC socket protection/endpoint exclusion,
Wi-Fi/cellular changes, cancellation, certificate rejection, sustained transfer
and thermal behavior. Native builds and unit/simulator tests do not establish
phone throughput. The TLS fallback also needs a separate capacity measurement.

## Build and regression checks

The final workspace suite passes 127 tests; the vendored upstream library suite
passes 317 tests. `cargo fmt --all -- --check`, report parser regressions and
lab shell syntax checks pass. The local patch was applied to pristine upstream
source and byte-compared with all three modified Rust files.

Native libraries were rebuilt for Android arm64-v8a and all five Apple targets.
Android unit tests and debug APK assembly pass; Swift passes 23 tests; the iOS
Simulator app build passes. macOS client/server release builds pass. These
checks validate builds and regressions, not physical-device throughput.

## Real WAN investigation (2026-11-08/09)

The user's macOS console client and VPS `103.74.92.168` reproduced an asymmetric
path: browser download 2–5 Mbps and upload 94–133 Mbps. Controlled iperf3 tests
used one VPN session and eight inner TCP flows; outer RTT was about 75–90 ms.
The Mac process initially remained the older CUBIC client while server variants
were compared. These are separate short runs, not simultaneous or hour-long
acceptance measurements.

| Measurement | Receiver Mbps | Notes |
| --- | ---: | --- |
| VPN TCP download, original CUBIC/default buffers | 6.47 | 12s measured |
| VPN TCP upload, original configuration | 155.49 | 12s measured |
| VPN download, CUBIC/GSO disabled | 11.95 | 20s; insufficient improvement |
| VPN download, BBR/original host buffers | 37.27 | 20s |
| VPN download, BBR/large host buffers | 59.01 | 25s |
| VPN download, CUBIC/large host buffers | 41.14 | 25s |
| VPN download, CUBIC/large buffers, 4 MiB TCP windows | 45.58 | 30s |
| VPN download, corrected BBR/large buffers, 4 MiB windows | 63.32 | 25s after 5s warmup |
| Direct TCP download outside VPN, eight flows | 183.63 | 20s |
| Direct UDP download, 100M offered | 99.94 | 0% reported loss |
| Direct UDP download, 200M offered | 166.61 | 16.61% reported loss |

A concrete additional loss point was Docker's host-side UDP proxy: its 212,992
byte socket buffers recorded hundreds of drops (923 on one connected socket).
The container's own UDP error counters stayed at zero. Increasing only Quinn's
queues did not configure these separate proxy sockets. The host now loads
[90-payphone-udp-buffers.conf](../deploy/90-payphone-udp-buffers.conf): defaults
4 MiB, maxima 16 MiB. Recreating PAYPHONE gave the proxy 4 MiB buffers and zero
recorded overflow in the subsequent checks. Other existing services were kept
running. These kernel defaults also apply to future UDP sockets on that host;
capacity is consumed as packets queue, rather than reserved for every socket.

The BBR experiment also exposed a startup growth guard comparing a dimensionless
gain against a byte count. The local correction compares cwnd against its modeled
target; a new regression covers application-limited startup. Upstream library
tests now total 317. GSO remains enabled; the GSO-off trial was reverted.

The current VPS image is recorded in `docs/node-103.74.92.168.md`. Temporary
iperf endpoints and their host access rules were removed. Raw evidence is in
ignored `runtime/node-103.74.92.168/speed-diagnosis/`.

**The 200–300 Mbps WAN goal is not met by these results.** The observed direct
UDP loss and corrected VPN rates do not identify a provider policy or establish
a hard physical upper limit. A restarted console client with QUIC counters and
longer controlled WAN measurements are still needed. Local-lab throughput is
not substituted for the user's browser download result.

### Repeat with the current corrected BBR profile

`runtime/perf-lab.XRhgpO/results/`: 50ms emulated RTT, eight TCP flows in one
VPN session, 10s warmup + 30s measured bidirectional TCP, then 10s UDP per
direction after 3s warmup. The complete report, automatic route repair and
SIGINT teardown passed. Minimum full one-second TCP receiver windows were
294.73 Mbps upload / 293.97 download; UDP minima were 292.01 / 299.16 Mbps,
with 0% reported loss in both directions. iperf reported TCP averages
302.09/320.94 Mbps against a 300M offered target; the overshoot is not treated
as a capacity ceiling. This short controlled repeat does not establish the
same rate on the actual WAN or replace the older 120s test.


### Complete BBR sampling fix (2026-11-09)

The first startup-guard correction was insufficient: the active server still
reported a congestion window of 185,473,259 bytes during ordinary usage. The
bandwidth filter rejected every application-limited sample and never aged a
higher estimate on lower non-limited samples. With a zero estimate, ACK
aggregation could inflate the modeled target again. The second local correction
accepts positive limited samples only when they raise the estimate, and all
positive non-limited samples. The paired conditions are also documented in
[Quinn PR #2798](https://github.com/quinn-rs/quinn/pull/2798); this remains a local
patch to the experimental controller, rather than a released upstream fix.

There are now five modified upstream Rust files. The exact patch was applied
to pristine crates.io 0.11.19 source and every Rust source file byte-compared.
All 320 upstream library tests and 127 workspace tests pass. Three additional
regressions cover limited samples from birth, expiry of an old peak, and bounded
controller cwnd over 100 paced application-limited rounds. Workspace formatting
and formatting of the edited vendor BBR files (edition 2024) pass; unrelated
upstream files were not reformatted.

An isolated candidate used port 8444 and the production certificate/verification
key/PSK and revocation list, with its own TUN, sessions and network namespace.
The same Linux client image, one VPN session, eight inner TCP flows and 4 MiB
TCP windows measured the following on the actual WAN. The iperf listener was
reachable only inside the authenticated VPN. No public iperf port was opened.

| Run | Receiver average Mbps | Full one-second windows, Mbps |
| --- | ---: | ---: |
| Current server, download, 25s after 5s warmup | 53.42 | 32.34–91.26 |
| Candidate, download, same duration | 103.30 | 25.28–179.05 |
| Candidate, simultaneous download, 60s after 10s warmup | 109.37 | 66.10–162.71 |
| Candidate, simultaneous upload, same session/run | 66.25 | Sender windows 35.70–110.10 |

The upload interval windows above are sender-side because this iperf version's
client JSON provides that direction's local sender intervals; averages are
receiver-side. The two short download runs are sequential, not a controlled
proof that every device will double its speed. Server CPU was about 28% and
its UDP proxy showed zero socket drops during a check under load. QUIC and TLS
smoke checks passed: auth, invalid resume denial, ping, rekey, DNS through both
stub and NAT, 1100-byte inner packet, resume over a new TLS connection and Close.

**Stable 200–300 Mbps on the real path is still not demonstrated.** The user's
phone result of about 60 Mbps is a separate observation, not the candidate's
controlled Linux-client result. Retain per-second windows when reporting rates;
a 179 Mbps peak does not satisfy the stability target.


The complete corrected profile also passed the isolated Linux TUN/NAT lab
`runtime/perf-lab.wiDIv8/results`: 50ms outer RTT, eight TCP flows/one VPN,
10s warmup + 60s simultaneous TCP, then 10s UDP per direction after 3s warmup.
TCP receiver averages were 310.13/315.49 Mbps against a 300M target (short-run
iperf accounting overshoot is not a capacity ceiling); minimum complete
one-second receiver windows were 283.29 upload / 281.82 download. UDP averages
were 299.98/300.01 Mbps, minima 299.91/299.77, reported loss 0% both ways.
Full report, automatic route repair and SIGINT teardown passed. This is a
controlled lab result and does not supersede the WAN measurements above.


Operational rollback: the candidate was promoted briefly, then restored to
`0.2.0-wan-bbrfix-20261108T191645Z` after the user reported broken connectivity.
The post-promotion long-lived test session retained QUIC control traffic but
its inner TCP test carried no data; the precise cause is unresolved. Do not
mark this candidate release-ready based on the fresh-connection smoke test.
A fresh session after rollback passed ICMP to 10.77.0.1 and 1.1.1.1, and the
old server image was healthy. All temporary WAN test listeners/containers and
the port-8444 candidate were removed. No throughput tests remain running.
The Mac route was subsequently observed through a separate VPSUS VPN; late
measurements are not comparable to the earlier physical path. iOS build3 was
built/signed but installation failed because the device became unavailable;
build2 remains the last confirmed installed version. Further updates were
stopped to prioritize restoring the user's connection.
