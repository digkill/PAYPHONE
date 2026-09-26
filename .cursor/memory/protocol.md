# Протокол PAYPHONE/1

Источник: `payphone-core`. Версия на проводе: `PROTOCOL_VERSION = 1`. Big-endian. Один QUIC datagram = один `Frame` (длина payload **точно** равна остатку после header). На TLS-stream: сначала 16 байт header, затем ровно `payload_len` байт.

## Frame header (16 байт)

| Смещение | Размер | Поле |
| ---: | ---: | --- |
| 0 | 1 | version (`1`) |
| 1 | 1 | `FrameType` |
| 2 | 2 | flags (сейчас `0`) |
| 4 | 4 | payload_len |
| 8 | 8 | sequence |

- `HEADER_SIZE = 16`
- `MAX_PAYLOAD_SIZE = 64 KiB`
- Sequence: сервер принимает кадр, если он не дальше чем **1024** позади максимума (`SEQUENCE_REORDER_WINDOW`). Точные дубликаты внутри окна проходят; целостность уже у QUIC/TLS.

Неизвестный `FrameType` или version ≠ 1 → ошибка decode, кадр отбросить.

## FrameType

| u8 | Имя | Направление | Payload |
| ---: | --- | --- | --- |
| 1 | `Data` | оба | 16 session_id + 8 packet_id + IPv4 packet (`DATA_HEADER_SIZE = 24`, max payload 64 KiB) |
| 2 | `WhatsUpDude` | C→S | header 41 + token (≤ 2048). Fields: proto u8, client_ver u16, caps u32, nonce 32, token_len u16, token |
| 3 | `AllGoodDude` | S→C | 59 байт: proto, session_id 16, ipv4 4, mtu u16, caps u32, server_nonce 32 |
| 4 | `Ping` | C→S | 24: session_id + ping_id u64 |
| 5 | `Pong` | S→C | 24, зеркало |
| 6 | `Rekey` | оба | 16 = Request (session_id); 48 = Token (session_id + nonce 32) |
| 7 | `Close` | оба | 17: session_id + reason u8 |
| 8 | `BackAgainDude` | C→S | 48: session_id + resume_token 32 (это server_nonce) |
| 9 | `StillGoodDude` | S→C | 26: session_id + ipv4 + mtu + caps (тот же адрес) |
| 10 | `AccessDeniedDude` | S→C | 9: reason u8 + expires_at u64 |

Имена кадров — часть протокола. Не переименовывать «для солидности».

## Capabilities (битовая маска u32)

| Бит | Константа | Сейчас |
| --- | --- | --- |
| 0 | `CAP_IPV4` | да |
| 1 | `CAP_IPV6` | клиент может ставить; сервер **не** согласовывает IPv6 |
| 2 | `CAP_DNS` | stub `10.77.0.1:53` |
| 3 | `CAP_RESUME` | да |
| 4 | `CAP_ROAMING` | клиент может ставить; сервер не поднимает roaming |

Сервер в handshake отдаёт `CAP_IPV4 | CAP_DNS | CAP_RESUME` (`handler.rs`).

## Handshake

```text
Client                         Server
  │ WhatsUpDude (token)           │
  │──────────────────────────────►│
  │     AllGoodDude               │  или AccessDeniedDude
  │◄──────────────────────────────│
  │ DATA / PING / REKEY / CLOSE   │
```

Resume (если есть `.payphone-session` и сессия ещё на диске сервера, подписка не истекла):

```text
  │ BackAgainDude                 │
  │──────────────────────────────►│
  │     StillGoodDude             │
  │◄──────────────────────────────│
```

Idle сессии: **300s** (`SESSION_TIMEOUT`). Входящий и исходящий валидный DATA обновляют активность, как и PING. `Close` снимает адрес сразу. `Ctrl+C` клиента шлёт `Close` и стирает локальный resume-файл.

## CloseReason

| u8 | Имя |
| ---: | --- |
| 0 | `ClientShutdown` |
| 1 | `ServerShutdown` |
| 2 | `Replaced` (другое устройство забрало слот) |

## DenyReason (`AccessDeniedDude`)

| u8 | Имя |
| ---: | --- |
| 1 | `InvalidToken` |
| 2 | `SubscriptionExpired` |
| 3 | `TokenRevoked` |
| 4 | `SubscriptionNotActive` |
| 5 | `UnknownSigningKey` |
| 6 | `UnsupportedPlan` |
| 7 | `InternalAuthError` |
| 8 | `DeviceLimitReached` |

## Rekey

Клиент может запросить ротацию resume-токена (`Rekey::Request`). Сервер предлагает новый nonce (`Rekey::Token`); клиент подтверждает тем же размером 48 байт. Сервер ACK подтверждения выдаёт только при переходе pending → current; дубликаты не вызывают цепочку ответов. Мобильный клиент сохраняет полученный nonce после handshake/resume и при серверной ротации. Интервал сервера: `REKEY_AFTER = 3600s`.

## Keepalive

Клиент: `PING` с джиттером **7–14s** (`PING_INTERVAL_MIN` + jitter до 7s). Quinn отдельно: idle timeout **180s**, QUIC keepalive **3s**. Таймер PING живёт вне `select!`, чтобы DATA/UI/route ticks не откладывали его бесконечно. Не ставить фиксированный метроном на 10.000s.

## DATA path

Сервер отвергает не-IPv4, неверные IHL/total length; IPv4 source клиента должен совпадать с assigned address; иначе дроп. Bandwidth: token-bucket по `max_mbps` (0 = без лимита). Device limit: при превышении вытесняется самая старая сессия этого `client_id` (`CloseReason::Replaced`).

Неизвестный resume или неверный nonce получает `AccessDeniedDude(InvalidToken)`: клиент может начать новый handshake. Отзыв/истечение подписки остаются окончательным отказом.
