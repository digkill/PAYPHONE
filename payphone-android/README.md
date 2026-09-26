# PAYPHONE for Android

Experimental Android client for the [PAYPHONE](../README.md) VPN protocol — Matrix hacker aesthetic, green-on-black, vertical digital rain, payphone glyphs.

**Protocol:** PAYPHONE/1 (same frames as `payphone-core`: `WhatsUpDude`, `AllGoodDude`, `Data`, …).  
**Transport today:** TLS on TCP **40443** (full tunnel via `VpnService`). QUIC/UDP is UI-ready; needs [`native/`](native/README.md) Rust bridge.

## Look & feel

- Black background, `#00FF41` monospace text
- Animated vertical rain (half-width katakana + digits + ☎)
- Copy from the desktop client: *Follow the white rabbit.*, *What's up, dude?*, *All good, dude.*
- Foreground VPN notification while connected

## Requirements

- JDK **26** to run Gradle (AGP 9.4 / Gradle 9.6). JDK 27 is not supported yet.
- Android SDK with platform 36 and Build-Tools 36.0.0
- Android 8.0+ (API 26) on the device
- A running PAYPHONE server (see repo root `README.md`)
- `subscription.token` (135 bytes) — Base64 in app settings
- Shared `PAYPHONE_OBFS_PSK` (≥16 chars, not the `.env.example` placeholder)
- VPN permission (system dialog on first connect)

## Quick test (TLS)

1. On your dev machine, start server + issue token (repo root):

   ```bash
   cargo run -p payphone-token -- setup 30 pro
   sudo ./target/debug/payphone-server --bind 0.0.0.0:40404
   ```

2. Export token and dev cert for the phone/emulator:

   ```bash
   base64 -i subscription.token
   base64 -i dev-certs/payphone-cert.der
   ```

3. Open **`payphone-android/`** as the project in Android Studio (not the Rust repo root). Gradle JDK must be **temurin-26** (Settings → Build → Build Tools → Gradle → Gradle JDK). The wrapper (`gradle-9.6.1`) and `org.gradle.java.home` in `gradle.properties` already pin the same JDK as `./gradlew`. Then **Sync Project with Gradle Files**.

4. Settings:
   - **Server:** LAN IP of your PC, port **40443** if you expose TCP, or use ADB reverse (below)
   - **Transport:** TLS :40443
   - **PSK:** same as server `.env`
   - **SNI:** `localhost` for dev cert
   - **Token / Pin:** Base64 strings from step 2

### ADB reverse (emulator → host server)

```bash
adb reverse tcp:40443 tcp:40443
# Server must listen TCP 40443 (default with payphone-server)
```

Then set server to `127.0.0.1:40443` in the app.

## Project layout

```text
payphone-android/
  app/src/main/java/com/payphone/android/
    protocol/     # PAYPHONE/1 codecs (Kotlin)
    transport/    # Obfuscation + TLS frame channel
    client/       # Handshake, session, ping jitter
    vpn/          # VpnService + TUN ↔ frames
    ui/           # Compose Matrix rain + connect screen
    data/         # Encrypted session + DataStore settings
  native/         # Planned Quinn JNI (QUIC)
```

## Build

```bash
cd payphone-android
export JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-26.jdk/Contents/Home
./gradlew assembleDebug
# or open in Android Studio
```

Unit tests (JVM, protocol roundtrip):

```bash
./gradlew test
```

## Full tunnel

When connected, the app installs:

- TUN address from `AllGoodDude` (`10.77.0.x/24`)
- Routes `0.0.0.0/1` and `128.0.0.0/1`
- DNS `10.77.0.1` (server stub)
- MTU from server (starts at 1100)

Server socket uses `VpnService.protect()` so the VPN app reaches the host outside the tunnel.

## Security notes

- Settings PSK and token live in DataStore / EncryptedSharedPreferences on device — treat the phone like a client laptop.
- Do not ship production signing keys or real PSK in the APK.
- TLS pin (DER Base64) is for dev self-signed; public hostname + system CAs work when SNI is a real DNS name.

## Roadmap

- [ ] Rust JNI: QUIC + UDP obfuscation (`native/`)
- [ ] SAF import for `subscription.token` file
- [ ] Optional kill-switch
- [ ] IPv6 blackhole routes on Android 13+ APIs
