# Android QUIC bridge

The app uses the shared `payphone-mobile` Rust crate: Quinn datagrams,
TLS 1.3 certificate/hostname verification and PAYPHONE UDP obfuscation.
The JNI shim carries unchanged encoded PAYPHONE frames; Kotlin owns the session handshake.

From the repository root:

```bash
rustup target add aarch64-linux-android
payphone-android/native/build.sh
# Optional emulator target:
rustup target add x86_64-linux-android
payphone-android/native/build.sh x86_64-linux-android
```

Set `ANDROID_HOME`/`ANDROID_NDK_HOME` if the SDK/NDK is outside the default
macOS SDK directory. Set `CARGO_BIN` when using a specific Rust toolchain.
The script writes `libpayphone_mobile.so` and `libpayphone_jni.so` into
`app/src/main/jniLibs/<abi>/`, ignored by Git. Libraries use 16 KiB page alignment.
Then run `./gradlew :app:assembleDebug` from `payphone-android/`.

QUIC uses the UDP server port (40404 locally, often 443 on a VPS).
TLS uses TCP 40443 locally. An absent pin uses WebPKI roots; an explicit
pin must be a DER certificate with the configured SNI in its SANs.

The native endpoint is opened before connecting. Kotlin calls
`VpnService.protect(fd)` on its UDP socket before any QUIC handshake.
Receive polling is bounded to 50 ms; closing wakes the reader. The app
continues to support TLS when the native libraries have not been built.

`cargo test -p payphone-mobile` checks the C ABI over a real local obfuscated
QUIC connection. Device routing, cancellation and throughput still need
physical Android testing.
