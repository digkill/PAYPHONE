# PAYPHONE local Quinn patch

Upstream: `quinn-proto` 0.11.19, from the published crates.io source.
Archive SHA256: `0e750cca55fe4f0439a15d0bb529da9651e79993e8e72c61a899a36d462befbe`.
MIT / Apache-2.0 licenses are retained. The crate's published version and wire
protocol are unchanged. `Cargo.toml.orig` records the upstream manifest.

Five Rust files differ from upstream; the exact changes are in
`replay-window.patch`. In `src/connection/spaces.rs`, the replay window grows
from 129 to 2048 authenticated packet numbers. A 256-byte ring bitmap avoids shifting the
whole window for every packet. Duplicates within the window and all packets
older than the window are still rejected. Missing-ACK-range queries use the
same retained horizon. Bitmap storage increases by 240 bytes per packet-number space (struct padding
depends on the target).

`src/connection/stats.rs` adds `PathStats.discarded_duplicate_packets`;
`src/connection/mod.rs` increments it when an authenticated packet is rejected
by the replay filter. This includes packets outside the retained window.
PAYPHONE reads this counter in its opt-in diagnostics, making a missing local
patch a build error. No packet contents or credentials are recorded.

`src/congestion/bbr/mod.rs` fixes the startup growth guard: compare the
current congestion window with the modeled target, rather than comparing the
dimensionless gain with a byte count. The old condition kept increasing cwnd
for application-limited traffic after it reached the target. A regression
checks bounded growth, gradual catch-up and the startup no-shrink rule.

`src/congestion/bbr/bw_estimation.rs` accepts positive application-limited
samples when they raise the bandwidth estimate, and lets lower non-limited
samples advance the peak filter's expiry window. Rejecting every limited sample
left bandwidth at zero for connections limited from birth; ACK aggregation
then inflated the modeled window despite the corrected startup guard. Two
estimator regressions check seeding, rejection of lower limited samples and
expiry of an old peak. A controller regression exercises 100 paced rounds
limited from birth and checks bounded cwnd. Both production conditions are
also described in [Quinn PR #2798](https://github.com/quinn-rs/quinn/pull/2798);
these are local fixes, not a released upstream change. They do not remove BBR
probe-RTT pauses or establish a WAN capacity guarantee.

Tests retain upstream behavioral cases, parameterize horizon-dependent cases,
and add delayed delivery beyond 129, boundary replay checks, and a set-oracle
comparison across wraps and gaps. All 320 library tests pass.
Run the upstream library tests with:

```sh
CARGO_TARGET_DIR="$PWD/target" cargo test --manifest-path vendor/quinn-proto/Cargo.toml --lib
```

The workspace pins this source via `[patch.crates-io]`. When upgrading Quinn,
rebase this small patch onto the security-maintained release, run the upstream
and workspace suites, then repeat the TUN/NAT performance lab. Update both VPN
ends: this is receiver-side behavior, with no new PAYPHONE frame or capability.

Background: [upstream reordering report](https://github.com/quinn-rs/quinn/issues/2710).
PAYPHONE's own temporary tracing reproduced hundreds of internal dedup discards
on the controlled delayed path, despite zero UDP socket errors. See
`docs/performance.md` in the repository root for measurements and limits.
