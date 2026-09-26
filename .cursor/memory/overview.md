# Обзор

PAYPHONE — экспериментальный **IPv4 VPN на Rust**, версия **0.2.0**, edition **2024**, минимум **Rust 1.85**. Прототип, не production VPN.

IP-пакеты с TUN едут в **QUIC datagrams** (Quinn) под **TLS 1.3**. Сессия открывается **Ed25519-токеном** подписки, не логином/паролем.

Репозиторий: [github.com/digkill/PAYPHONE](https://github.com/digkill/PAYPHONE).

Android-клиент (Kotlin, Matrix UI): [`payphone-android/`](../payphone-android/README.md) — TLS на :40443; QUIC через planned `native/`.

## Зачем так, а не WireGuard

Цель — свой стек и транспорт, который **не выглядит как голый QUIC** на проводе (DPI пассивно матчит long header / version; активный probe завершает handshake и блоклистит IP).

Это не «замена WireGuard» и не инструкция обхода блокировок. Inner protocol всегда кадры PAYPHONE, **не VLESS/Vision**.

## Что работает (коротко)

- Двусторонний IPv4 через TUN; full-tunnel (`0.0.0.0/1` + `128.0.0.0/1`) на macOS / Linux / Windows.
- Два транспорта на одном хосте: **UDP** (обфусцированный QUIC) и **TCP 443** (лендинг HTTPS + опциональный REALITY).
- Handshake: `WhatsUpDude` → `AllGoodDude`; resume: `BackAgainDude` → `StillGoodDude`.
- Сессии на диске; idle timeout **5 минут**; `Close` сразу освобождает VPN-адрес; `Rekey` раз в час.
- Лимиты устройств и Mbps из токена; отзыв `token_id` из файла.
- DNS stub на `10.77.0.1:53`; клиент пинит его (fail-closed к ISP DNS).
- Let's Encrypt (TLS-ALPN-01) при `PAYPHONE_TLS_DOMAIN`, либо pin self-signed leaf.

## Чего нет (намеренно)

- IPv6 в туннеле. С клиента AAAA глушится blackhole `::/1` + `8000::/1`.
- Roaming (клиент может рекламировать capability, сервер не согласовывает).
- Распределённый revoke store (только файл).
- REALITY по умолчанию **выключен**. В Coolify не включать, пока dest + ключи не заданы.

## Топология адресов

| Где | Адрес |
| --- | --- |
| VPN-подсеть | `10.77.0.0/24` |
| Сервер внутри туннеля | `10.77.0.1` |
| Клиенты | с `10.77.0.2` |
| Контейнер QUIC | `40404/udp` (`payphone_core::DEFAULT_PORT`) |
| Контейнер TCP (лендинг / REALITY) | `40443/tcp` (`DEFAULT_TCP_PORT`) |
| Прод (хост) | обычно `443/udp` + `443/tcp` → контейнерные порты |

Локальное демо: UDP `40404`. На одном Linux-хосте оба бинарника хотят TUN `payphone0` — нужны netns или разные имена.
