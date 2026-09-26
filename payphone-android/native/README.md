# QUIC native bridge (planned)

Android has no stable pure-Kotlin QUIC **datagram** stack that matches PAYPHONE's Quinn setup. The desktop client uses `payphone-transport` (Quinn + UDP obfuscation).

## Current Android transport

- **TLS (default in the app UI):** TCP `:40443`, TLS 1.3, ALPN `http/1.1`, same PAYPHONE frames as QUIC. Works against a running `payphone-server` HTTPS front.
- **QUIC (UDP):** UI option is wired; connection returns an error until this native module ships.

## Planned layout

```text
payphone-android/native/
  Cargo.toml          # cdylib, depends on payphone-core + payphone-transport
  src/lib.rs          # JNI: connect, send_datagram, recv_datagram, close
  build.rs            # optional
```

Build with [cargo-ndk](https://github.com/bbqsrc/cargo-ndk):

```bash
cargo ndk -t arm64-v8a -t x86_64 -o app/src/main/jniLibs build --release
```

JNI surface (sketch):

| Method | Role |
| --- | --- |
| `nativeConnect(host, port, psk, token, pinDer)` | QUIC handshake + PAYPHONE session |
| `nativeSend(handle, frameBytes)` | Obfuscated QUIC datagram |
| `nativeRecv(handle)` | One PAYPHONE frame or timeout |
| `nativeClose(handle)` | `Close` frame + QUIC shutdown |

Kotlin wraps this in `QuicFrameTransport : FrameTransport`.

## Until native lands

Point the app at **`your-server:40443`** with transport **TLS**. For local dev with self-signed cert, paste Base64 of `dev-certs/payphone-cert.der` into the pin field and set SNI `localhost`.

Obfuscation PSK must match the server (`PAYPHONE_OBFS_PSK`) even on TLS path — the server still validates it at process start; the Android TLS path does not send obfuscated UDP, but PSK is reused for encrypted session resume storage.
