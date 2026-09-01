# I built a VPN that refuses to look like a VPN

A censor doesn't need to read your traffic. It needs to *classify* it. That distinction is the whole reason this project exists, and it's the thing most weekend-VPN writeups skip past on their way to a WireGuard config file.

PAYPHONE is a Rust VPN I've been building that carries IPv4 packets inside QUIC datagrams, wraps the QUIC datagrams in a lightweight obfuscation layer, and authenticates sessions with Ed25519-signed tokens. None of that is novel by itself. What's worth writing about is everything that went wrong on the way to "it works" — because almost none of it was where I expected.

## The actual threat model

Deep packet inspection systems built for state-level censorship (Russia's TSPU is the one I care about, but the shape generalizes) mostly don't try to decrypt anything. Decryption is expensive and TLS 1.3 makes it a non-starter anyway. What they do instead:

- **Passive signature matching.** QUIC's long header — version field, connection ID lengths, the general shape of an Initial packet — is recognizable on the wire regardless of which port it's running on. "Run your QUIC server on 443" doesn't fix this; the bytes are still QUIC bytes.
- **Active probing.** See a suspicious UDP flow to some IP:port, dial it yourself, try to complete a QUIC handshake. If the far end answers like a real QUIC endpoint, blocklist it. This is more expensive than signature matching but not *that* expensive, and it catches things the passive matcher misses.
- **Traffic-shape classification.** Even without reading a single byte or attempting a handshake, a sustained encrypted UDP flow to one IP:port, with periodic small keepalives and one dominant packet-size cluster, has a shape. VPNs have a shape. Video calls have a different shape. A censor that's good at this doesn't care what protocol you're speaking.

Most of what people build to "get around DPI" only answers the first bullet. PAYPHONE's obfuscation layer answers the first two and is explicit about not answering the third — more on that below, because pretending otherwise is how you end up shipping something that gives its users false confidence.

## Frame names as documentation

Every PAYPHONE message is one QUIC datagram with a 16-byte header (version, frame type, flags, payload length, sequence — all network byte order, all length-checked before anything downstream touches them) and a small set of frame types:

| Frame | Direction | Purpose |
| --- | --- | --- |
| `WhatsUpDude` | client → server | opens a session, carries the subscription token |
| `AllGoodDude` | server → client | assigns a VPN address, hands back a resume secret |
| `BackAgainDude` / `StillGoodDude` | client ↔ server | resume an existing session without a new token |
| `AccessDeniedDude` | server → client | token expired, revoked, wrong signing key |
| `Data` | both | an actual IPv4 packet |
| `Ping` / `Pong` | both | keepalive |

Yes, the names are ridiculous on purpose. Six months from now, `WhatsUpDude` tells me exactly what this frame does without opening the docs. `HandshakeInitRequest` doesn't, and I've spent too many hours in codebases full of frame types that all sound identical and behave differently. Naming things that make you smile is a legitimate engineering tactic when the alternative is naming things that make you check three files to remember what they do.

## Datagrams, not streams, and why that almost bit me

VPN traffic is IP, and IP already tolerates loss — that's the entire point of having a transport layer above it. If you tunnel that inside a *reliable* QUIC stream, you get TCP-over-TCP: the inner protocol's own loss recovery fights the outer one's, retransmissions stack on retransmissions, and everything gets worse under exactly the conditions where you need it to get better.

So `Data` frames ride QUIC's unreliable datagram extension. Lose one, the inner TCP/QUIC connection notices and recovers on its own; Quinn drops the oldest buffered datagram under backpressure instead of blocking, which is the right failure mode for a tunnel.

The first version of the send path awaited every `send_datagram_wait()` call. Under real load this serialized outbound and inbound: the TUN-to-QUIC direction would block on a slow write, and the same select loop that was supposed to be servicing QUIC-to-TUN in parallel just... didn't, until the write finished. One `send_datagram_wait` → `send_datagram` + explicit handling of the size-limit error fixed it. I mention this not because it's a hard bug — it's an embarrassingly simple one — but because it's exactly the kind of thing that only shows up under load, never in a two-terminal manual test, and I'd bet money it's sitting unnoticed in more tunnel implementations than the one I just fixed it in.

## Obfuscation is not encryption, and I want to be annoying about that distinction

Confidentiality is TLS 1.3's job. It already has it. What sits on top is a much dumber layer whose only job is making PAYPHONE datagrams stop looking like QUIC datagrams:

```
[ 8-byte random salt ][ XOR(
    tiled SHA256(shared_secret || salt),
    [2-byte length][real payload][0–32 random padding bytes]
) ]
```

Salamander, from Hysteria2, if you want the lineage. A fresh salt every packet means identical plaintext never produces identical ciphertext on the wire. The length prefix lets the receiver strip the padding tail. And critically: a datagram that doesn't decode with the correct shared secret gets dropped *before it ever reaches the QUIC layer*. An active prober without the secret doesn't get a QUIC error, doesn't get a TLS alert, doesn't get anything. Silence. There's no signal to distinguish "wrong secret" from "nobody's listening on this port at all," which is exactly the property you want against a prober that's trying to confirm a server exists.

What it does *not* do — and I think glossing over this is the most common failure mode in DIY-obfuscation writeups — is hide the fact that a tunnel exists. A censor doing traffic-shape classification doesn't need to know your protocol's name. It needs: non-standard-looking encrypted UDP, one long-lived flow, a keepalive with a suspiciously regular period, a server that answers some IPs and not others. PAYPHONE's obfuscation defeats the first two threat-model bullets from earlier and is honest about not touching the third.

Looking like a real HTTPS visit to a real site is a different transport. PAYPHONE now has that as optional REALITY on TCP 443 (`PAYPHONE_REALITY=on`, default off). A probe that fails Xray's `session_id` check is TCP-spliced to a real dest (`www.microsoft.com:443` in the docs). An authenticated ClientHello gets dest's ServerHello (JA3S, only the X25519 `key_share` rewritten), dest encrypted-record sizes, and three dest post-handshake probes by ALPN class (none / `http/1.1` / `h2`). EncryptedExtensions *content* is inside AEAD; we echo the client's ALPN and copy dest *sizes*. The ClientHello follows uTLS `HelloChrome_131` — GREASE pinned at both ends, shuffled middle, GREASE ECH, a real ML-KEM-768 public plus X25519. Bit-identical to a live Chrome capture is the wrong goal: GREASE/ECH/KEM are random every hello, and Chrome itself ships a new shape most months.

Inner frames stay PAYPHONE, not VLESS/Vision. An Xray client that happens to share keys can pass the outer handshake and then hits the wrong protocol. Coolify still does not turn REALITY on by default. When dest + keys are set, enable it: if `PAYPHONE_TLS_DOMAIN` is also set, browsers hitting **your** name still get the landing page (and Let's Encrypt TLS-ALPN-01 still works on that SNI). Other ClientHellos splice to dest.

## The bug that taught me to read RFC 9000 more carefully

Here's the one I'm actually proud of catching, because the failure mode was subtle enough that my first fix attempt didn't work either.

Early obfuscation padding rounded every outgoing datagram's length up to the nearest of a handful of buckets — 128, 296, 568, 1200, 1440 bytes — the idea being that a fixed set of common sizes is harder to fingerprint than a length that tracks the real payload byte-for-byte. Reasonable-sounding. Wrong in a way that only showed up in production.

Every packet Quinn sends passes through this obfuscation layer — *including its own internal path MTU discovery probes.* A probe sitting just above 1200 bytes unpadded got rounded straight to 1440: a 240-byte jump. If that inflated probe didn't survive the real path MTU, Quinn concluded the *smaller* size didn't work either and lowered its usable datagram budget accordingly. Do that enough times and the connection's own idea of "how big a datagram can I send" ratchets down until an honest, full-size application packet gets rejected with `SendDatagramError::TooLarge`. On a live deployment, mid-browsing-session, with no warning.

I swapped the buckets for a small uniform random pad (0–32 bytes) instead, redeployed, and hit the exact same error.

That's when I actually went and read `quinn-proto`'s source instead of guessing. The numbers, worked out from the actual code:

- QUIC guarantees nothing above a 1200-byte path MTU until discovery succeeds (RFC 9000). Quinn's `min_mtu` and `initial_mtu` both default to that floor, and black-hole detection resets back to it on loss.
- Quinn reserves roughly 46 bytes of that for its own overhead — 1-byte flags, 8-byte connection ID, up to 4 bytes of packet number, a 16-byte AEAD tag, 17 bytes of DATAGRAM frame overhead. Call it a guaranteed **~1154-byte** budget per datagram, independent of anything the padding layer does.
- PAYPHONE's own framing adds 40 bytes on top of the raw IP packet (16-byte frame header, 24-byte DATA header).
- The tunnel's MTU was 1280. Worst case: **1320-byte frame**, against a guaranteed 1154-byte ceiling. A 166-byte overshoot that had nothing to do with my padding bug at all — it was there from day one, just usually masked by MTU discovery completing before a large-enough packet needed to go out.

The actual fix was one constant: drop the tunnel MTU to 1100, so the worst case (1140 bytes) sits inside the guaranteed floor regardless of whether discovery has run yet. Then I wrote a regression test that opens a real connection over loopback and sends a max-size frame *immediately* after the handshake completes — no time for discovery to help — and confirmed it reproduces `TooLarge` at the old MTU and passes at the new one. Then, because loopback tests have a way of passing for reasons that don't hold up over a real network, I wrote a second throwaway binary that runs the actual client code against the actual deployed server and sends the actual worst-case frame over the actual internet before I trusted the fix at all.

The lesson, stated plainly: "1280 is safe, it's the RFC-recommended IPv6 minimum" is a true fact about IP that says nothing about the datagram budget of whatever's sitting on top of your MTU. Check the real number for the actual protocol you're using. I didn't, the first time.

## The other lesson: don't trust the "port is published" checkbox

Deploying behind Coolify (or any PaaS with a generic "ports" UI) taught me something that has nothing to do with QUIC: a lot of these tools' port-mapping fields quietly only support TCP. Ask for a `/udp` suffix and you get a validation error, or worse, silent acceptance that does nothing. `docker ps` will happily show you `40404/udp` with no host binding at all — *exposed*, not *published* — and your UDP packets will die at the host's network interface with zero application-level visibility into why, because they never got anywhere near your application.

`tcpdump -i any -n udp port 40404` on the host settled it in about ten seconds: packets arriving at `eth0`, nothing reaching the container. The fix was routing the deploy through a real Compose file with a native `ports: - "40404:40404/udp"` entry instead of the platform's abstraction over it. If you're deploying any UDP-based service behind a PaaS, save yourself the debugging loop and just check this first.

## What I'm not going to pretend is finished

IPv6 is blackholed on the client (`::/1` and `8000::/1` on macOS, Linux, and Windows) rather than left to leak past the tunnel — the server doesn't route it yet, so "fail to IPv4 in the tunnel" beats "silently leaking your real address." Windows full-tunnel is `/1` split routing plus a host route for the server, `wintun.dll`, Administrator, and DNS pinned to `10.77.0.1` on the TUN adapter. Sessions live on disk; restart the server and clients can resume. Token revocations are a file of hex `token_id`s (`payphone-token revoke`); the server re-reads on mtime, no restart. The subscription token format carries a device-count limit and a bandwidth cap and now enforces both. UDP GSO/GRO is on in `ObfuscatedSocket` so bulk TUN traffic is one syscall per batch on Linux. None of this is hidden; it's the actual current state, and the honest version of "what works" is more useful to the next person than a README that oversells it.

## Why the client prints digital rain before it connects

No defensible technical reason. I got tired of staring at a blinking cursor while `sudo` did its thing, so the client draws a green digital-rain intro before the handshake starts and the same falling glyphs pulse alongside a live packet counter once the tunnel is actually pushing traffic. It doesn't make the tunnel faster or safer. It does make running `sudo ./payphone-client` for the fortieth time in a debugging session marginally less soul-crushing, and given how much of this project turned out to be macOS routing tables and off-by-one MTU math, I'll take marginally.
