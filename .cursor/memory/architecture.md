# Архитектура

Cargo workspace, resolver `"2"`, восемь крейтов. Зависимости направлены **внутрь**: бинарники → transport/tun/auth → core. `payphone-core` **не** знает про Ed25519, QUIC, TUN.

```text
payphone-client ──┐
payphone-server ──┼── payphone-transport ── payphone-core
                  ├── payphone-tun
                  └── payphone-auth
payphone-token ────── payphone-auth ────── (нет core)
```

| Крейт | Роль | Бинарь |
| --- | --- | --- |
| `payphone-core` | Wire: `Frame`, типы, кодеки, константы, валидация длин | нет |
| `payphone-auth` | Claims, Ed25519, key ring, verifier, revoke store | нет |
| `payphone-token` | CLI: `init` / `issue` / `setup` / `revoke` / `reality-init` | `payphone-token` |
| `payphone-transport` | Quinn endpoints, TLS identity/ACME, UDP obfuscation, HTTPS front, REALITY | нет |
| `payphone-tun` | Async TUN, IPv4 helpers, full-tunnel routing / NAT / kill-switch | нет |
| `payphone-server` | Auth, сессии, DNS stub, TUN↔wire | `payphone-server` |
| `payphone-mobile` | Общий мобильный QUIC C ABI; Android JNI / Apple XCFramework | staticlib / cdylib |
| `payphone-client` | Handshake, TUN forward, keepalive, resume file, Matrix TUI | `payphone-client` |

## Поток данных (UDP / QUIC)

```text
app / kernel
    │
    ▼
TUN (клиент)  →  Frame{Data}  →  QUIC datagram + TLS 1.3  →  obfuscate UDP  →  сеть
TUN (сервер)  ←  Frame{Data}  ←  QUIC datagram + TLS 1.3  ←  deobfuscate     ←  сеть
```

На сервере destination VPN-адреса мапятся на живые сессии. Пакеты от клиента принимаются **только** если IPv4 source совпадает с выданным сессии адресом.

TCP-путь (`PAYPHONE_TRANSPORT=tls`): те же кадры, length-prefix по 16-байтовому header (`Frame::payload_len_from_header`), **без** UDP-обфускации.

## Почему datagrams, не QUIC streams

VPN возит IP. IP уже теряет пакеты. Надёжный stream даёт TCP-over-TCP (HOL, двойной ретрансмит). Payload — **unreliable datagram**. Переполнение буфера Quinn: дропать, не ждать. На горячем пути: `payphone_transport::send_vpn_datagram` → `connection.send_datagram`, **не** `send_datagram_wait`.

## Границы ответственности

- **core** — байты кадра. Токен в `WhatsUpDude` — непрозрачные bytes (макс. 2 KiB).
- **auth** — разобрать и проверить 135-байтный `PAYT` token. Не знает про TUN.
- **transport** — как кадр доезжает: UDP obfuscation, Quinn, rustls, REALITY splice. Не знает claims.
- **tun** — интерфейс и таблица маршрутов ОС. Не знает кадры.
- **server `session.rs`** — логическая сессия, store `PAYS`, rate limit, device limit, sequence window.
- **server `handler.rs`** — dispatch `FrameType` → create/resume/data/ping/rekey/close.

## Ключевые файлы

| Путь | Что |
| --- | --- |
| `payphone-core/src/lib.rs` | Header, `FrameType`, encode/decode |
| `payphone-server/src/handler.rs` | Серверный протокол |
| `payphone-server/src/session.rs` | `SessionManager`, persist, limits |
| `payphone-client/src/main.rs` | Клиентский цикл, ping jitter |
| `payphone-client/src/tunnel.rs` | TUN ↔ кадры |
| `payphone-transport/src/lib.rs` | Quinn `TransportConfig` (BBR со startup/sampling fixes, idle 180s) |
| `payphone-tun/src/routing.rs` | Full-tunnel, NAT, IPv6 blackhole |

## Рантайм

Tokio multi-thread. Сервер: concurrent клиенты; cleanup сессий каждые 5s. Клиент: TUN, datagrams, ping, SIGINT. Resume-файл клиента — `.payphone-session` (ChaCha20-Poly1305). Store сервера — `payphone-sessions.bin` / `PAYPHONE_SESSION_STORE`.

## Нагрузка

Серверный TUN→wire работает в отдельной задаче `forward.rs`, независимо от accept/cleanup. `SessionManager.by_ipv4` — индекс для O(1) маршрутизации; обновлять при любом удалении/создании/восстановлении. Пул `/16`: 65 533 адреса, это предел адресации, не доказанная ёмкость сервера. Benchmark транспорта: `cargo run --release -p payphone-transport --example bench_datagrams -- 1 100 5`; исключает TUN/NAT/auth и мобильные bindings.

Локальная transport dependency: vendor/quinn-proto (не workspace member), patch crates.io0.11.19 с2048-PN replay window. Исходник/лицензии и delta задокументированы в PATCHES.md; собственных крейтов по-прежнему8.

2026-11-09 connection recovery: iOS App ContentView used fresh @State settings and never restored NETunnelProviderProtocol.providerConfiguration. Build4 restores server/transport/SNI/PSK/binary token/pin from this app’s saved profile, filters manager by own extension bundle, updates status on load, allows disconnect even with empty UI settings, validates required fields before overwriting saved profile. Secrets are already in existing NE preferences; no new secret store/baked config. Removed incorrect comment claiming settings secrets are stored separately in Keychain. Signed build4 installed on connected iPhone; runtime/ios/20261109-build4/Payphone-1.0-build4.ipa. For recovery, bundled entire tunnel extension from known installed build2, changed only bundle version/re-signed: PayphoneTunnel.debug.dylib SHA byte-identical to build2, recorded in tunnel-engine-sha256.txt. Plain xcodebuild would relink current native artifacts; this recovery IPA is a post-build assembly retaining the old engine. Server stays BBR firstfix191645, fresh QUIC+TLS auth/rekey/DNS/NAT/resume probes pass; physical user connection still needs verification. Mac currently VPSUS, own CLI not running, no noninteractive sudo. Do not claim all devices restored based on these probes.
