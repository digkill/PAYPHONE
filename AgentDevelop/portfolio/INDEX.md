---
tagline: Экспериментальный IPv4 VPN на Rust: TUN внутри QUIC+TLS, подписка Ed25519.
audience: Инженеры и свой стенд; не замена WireGuard для широкой аудитории.
purpose: Свой стек туннеля и транспорт, который на проводе не выглядит как голый QUIC.
problems_solved: Понять VPN целиком. DPI пассивно узнаёт QUIC; активный probe завершает handshake. Нужны datagrams, а не TCP-over-TCP.
functions: TUN↔QUIC datagrams, TLS 1.3 / Let's Encrypt, XOR-обфускация UDP, optional REALITY на TCP 443, токены, full-tunnel, kill-switch.
achievements: Workspace из 7 крейтов, v0.2.0, статьи на Habr/dev.to, клиент macOS/Linux/Windows, сессии на диске.
---

# PAYPHONE — портфолио

Экспериментальный VPN. Репозиторий: [github.com/digkill/PAYPHONE](https://github.com/digkill/PAYPHONE). **Не production.**

## Для бизнеса

Это **R&D и демонстрация системного Rust**, не продукт с SLA. Для презентации: «собрали туннель с нуля — TUN, QUIC, подписки, обфускация, full-tunnel на трёх ОС». Не продаём как «обход блокировок». Inner protocol — кадры PAYPHONE, не VLESS.

Возможный следующий шаг продукта — отдельный бренд с нормальным TLS, биллингом и без self-signed по умолчанию.

## Что умеет

- IPv4 `10.77.0.0/24`, сервер `.1`, клиенты с `.2`.
- Handshake `WhatsUpDude` / `AllGoodDude`, resume, revoke токенов, лимиты устройств и Mbps.
- UDP 40404 (в проде часто 443/udp) + TCP 443 (лендинг / REALITY).
- Kill-switch опционален; IPv6 в туннеле нет (AAAA глушится).

## Скрины

В README репозитория есть схема туннеля (`assets/…png`). Скопируйте схему и кадры CLI/Coolify в [`screenshots/`](screenshots/).
