---
title: Документация PAYPHONE
---

# Документация

Память: [`.cursor/memory/README.md`](../../.cursor/memory/README.md). Человеческие тексты: `README.md`, `docs/habr-payphone.md`, `docs/devto-payphone.md`. При расхождении **код побеждает**.

## Крейты

`payphone-core` (кадры) · `payphone-auth` / `payphone-token` · `payphone-transport` (QUIC, TLS, REALITY) · `payphone-tun` · `payphone-server` / `payphone-client`.

## Инварианты

- IP только в **QUIC datagrams**, hot path `send_datagram`, не `send_datagram_wait`.
- Стартовый MTU TUN **1100**. UDP padding **0–32** байт, без size buckets.
- Внутри не VLESS. REALITY default-off.
- Не коммитить `subscription-private.key`, `.env`, токены, сертификаты.
- macOS: не чинить IPv6/DNS через `networksetup`; маршруты снимать до `wait_idle` на SIGINT.
