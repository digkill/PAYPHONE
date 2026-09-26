# Архитектура

Cargo workspace, resolver `"2"`, семь крейтов. Зависимости направлены **внутрь**: бинарники → transport/tun/auth → core. `payphone-core` **не** знает про Ed25519, QUIC, TUN.

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
| `payphone-transport/src/lib.rs` | Quinn `TransportConfig` (BBR, idle 180s) |
| `payphone-tun/src/routing.rs` | Full-tunnel, NAT, IPv6 blackhole |

## Рантайм

Tokio multi-thread. Сервер: concurrent клиенты; cleanup сессий каждые 5s. Клиент: TUN, datagrams, ping, SIGINT. Resume-файл клиента — `.payphone-session` (ChaCha20-Poly1305). Store сервера — `payphone-sessions.bin` / `PAYPHONE_SESSION_STORE`.
