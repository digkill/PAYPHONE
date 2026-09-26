# Транспорт

Крейт `payphone-transport`. Клиент выбирает `PAYPHONE_TRANSPORT=quic` (default) или `tls` (алиасы: `udp`, `https`, `tcp`).

## UDP / QUIC (основной путь)

- Quinn + rustls-ring, TLS 1.3. Datagrams, не streams.
- Обфускация **каждого** UDP datagram до сокета (`obfuscation.rs` + `ObfuscatedSocket`).
- На Linux: GSO/GRO в `ObfuscatedSocket`; Quinn `enable_segmentation_offload(true)`.
- `vpn_transport_config()`: BBR (не Cubic), idle 180s, keepalive 3s, initial RTT 50ms, datagram buffers 8 MiB, MTU discovery upper bound 1452.

Неверная PSK: datagram не деобфусцируется → **тишина**, Quinn не видит handshake. Это защита от слепого active probe.

### Обфускация (не шифр)

Стиль Hysteria2 Salamander. Конфиденциальность уже у QUIC TLS.

```text
[ 8 B salt ][ XOR( tiled SHA256(SHA256(psk) || salt),  [u16 BE length][payload][pad 0–32] ) ]
```

- PSK: SHA256 → 32-byte key. Одинаковый на клиенте и сервере.
- `validate_passphrase`: минимум 16 символов; запрещён placeholder `change-me-to-a-real-random-secret`.
- Padding **равномерный 0–32 байта**. **Не возвращать бакеты** `[128, 296, 568, 1200, 1440]` — они ломали PMTU Quinn (проба 1200 прыгала в 1440).
- `PAYPHONE_DEV_MODE=true`: лог raw UDP до обфускации. По умолчанию `false` (тишина к чужому трафику — часть модели).

Обфускация **не** прячет: один долгоживущий 4-tuple, кластеризацию размеров QUIC, «сервер отвечает не всем», нестандартный порт если слушать не 443.

## TCP / HTTPS front

Порт контейнера `40443` (хост часто 443). ALPN `http/1.1`.

- Браузер / probe `GET` → маленькая лендинг-страница (`https_front.rs`, «Follow the white rabbit.»).
- PAYPHONE-клиент после TLS пишет те же кадры length-prefixed.
- UDP obfuscation **не** применяется.
- Серверная очередь TLS использует `try_send`: при заполнении отбрасывает новый кадр, не блокируя общий TUN-loop. Управляющие кадры тоже могут быть потеряны; handshake ограничен тайм-аутом.
- Мобильные TLS read/send/connect закрывают соединение при отмене; после тайм-аута resume создаётся новый stream. Пустой pin в Apple означает системное доверие. Android проверяет hostname при системном CA.
- `PAYPHONE_TCP_BIND_ADDR=off` выключает TCP. Иначе default: IP UDP-bind + порт 40443.
- Клиент: если UDP порт 40404 и `PAYPHONE_TCP_SERVER_ADDR` не задан — TCP цель автоматически `:40443`.

## TLS identity

Сервер (`identity.rs` / `tls.rs`):

1. Self-signed `dev-certs/payphone-cert.der` + `payphone-key.der`, SNI по умолчанию `localhost`. Клиент пинит leaf (`PAYPHONE_TLS_PIN`).
2. PEM/DER `--tls-cert` / `--tls-key` (`PAYPHONE_TLS_CERT` / `PAYPHONE_TLS_KEY`), reload по mtime.
3. Let's Encrypt: `PAYPHONE_TLS_DOMAIN`, TLS-ALPN-01 на том же TCP 443. Кэш ACME: `PAYPHONE_ACME_DIR` (в Docker `/app/state/acme`). Staging: `PAYPHONE_ACME_STAGING`.

Клиент: публичное DNS-имя в `--server` ⇒ SNI = hostname и `--tls-ca system` (WebPKI), pin не обязателен. Явный `PAYPHONE_TLS_CA=pin` оставляет pin.

## REALITY (опционально, только TCP)

Default **off**. `PAYPHONE_REALITY=on` + dest + X25519 + shortId. Inner = PAYPHONE, не VLESS. Xray-клиент с теми же ключами пройдёт outer handshake и упрётся в чужие кадры.

Схема как у XTLS/Xray:

- **Outer:** ClientHello `session_id` = X25519 + HKDF-SHA256 `"REALITY"` + AES-256-GCM. Версия в session_id: `CLIENT_VERSION = [0, 2, 0]`.
- Не авторизованный hello → **TCP splice** на `PAYPHONE_REALITY_DEST` (живой TLS 1.3 сайт с VPS).
- Авторизованный → ephemeral Ed25519 cert, подпись **HMAC-SHA512(AuthKey, pubkey)** (проверка как Xray `VerifyPeerCertificate`). Клиенту pin не нужен; SNI dest: `--reality-sni`.
- Если задан `PAYPHONE_TLS_DOMAIN`: ClientHello на **это** имя → свой лендинг + ACME; остальные → splice/REALITY.

ClientHello: форма **Chrome 131** (GREASE края, shuffle середины, GREASE ECH, ALPN `h2`+`http/1.1`, X25519MLKEM768 + X25519). Hybrid share несёт настоящий ML-KEM-768 public; VPN завершается на **X25519**. Свой TLS 1.3 stack (`reality/tls13.rs`), чтобы CertificateVerify мог быть Ed25519 HMAC (Chrome не рекламирует ed25519 в `signature_algorithms`). Не бит-в-бит дамп живого Chrome.

ServerHello после auth: копия dest, патч только X25519 `key_share` (JA3S dest). Suites: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305. Dest мёртв → свой ServerHello.

Encrypted record sizes: как у dest (handshake + post-handshake `0x17` из трёх фоновых проб ALPN none / http/1.1 / h2). **Не копировать plaintext EncryptedExtensions dest** — он внутри AEAD, ключей dest нет; эхоим ALPN клиента.

Ключи: `payphone-token reality-init` → `auth-keys/reality-private.key`, `reality-public.key`, `reality-short-id.txt`.

Не включать REALITY в Coolify, пока dest и ключи не лежат рядом с деплоем.
