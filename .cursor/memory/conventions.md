# Соглашения для агентов

## Стиль кода

- Rust 2024. Версия крейтов **0.2.0** — bump согласованно во всех `Cargo.toml`.
- Не добавляй зависимости «на всякий случай». Quinn / rustls / dalek / tun-rs уже выбраны.
- Комментарии в `payphone-core` и части auth — подробные, часто русские. В transport/client/server — английские, по делу. **Не размазывай** новые файлы комментариями в стиле учебника; в старых модулях не переписывай тон ради единообразия.
- Имена кадров (`WhatsUpDude`, …) не «улучшать».
- Ошибки: `thiserror` в core/auth; в бинарниках часто `Box<dyn Error>`. Decode строго по длине — не «догадываться» о хвосте.

## Что не ломать

1. Datagrams, не QUIC streams, для IP.
2. `send_vpn_datagram` / `send_datagram` на горячем пути, не `send_datagram_wait`.
3. Обфускация: pad 0–32, без size buckets.
4. TUN MTU старт 1100; бюджет считать как IP + 40 байт PAYPHONE.
5. Inner protocol = PAYPHONE. Не тащить VLESS/Vision «для совместимости с Xray».
6. REALITY default off. Не включать в compose сервера без dest+ключей.
7. Private subscription key не копировать в Docker image.
8. PSK обязателен и не равен placeholder.
9. macOS routing: никакого `networksetup` для IPv6/DNS.
10. Teardown: маршруты снять до `wait_idle`.

## Тесты

`cargo test --workspace`. Юниты: кадры, auth, persist сессий, лимиты, IPv4 parse, TLS identity, bind Quinn, obfuscation roundtrip, mismatch PSK, max-size datagram сразу после handshake (регрессия TooLarge).

Тест endpoint открывает локальный UDP — не мокай сеть до нуля, если проверяешь сокет.

## Документация

- Пользователю: `README.md` (EN).
- Статья: `docs/habr-payphone.md`; бриф: `docs/habr-article-prompt.md`.
- Память агентов: `.cursor/memory/` — обновляй вместе с инвариантами.
- Не пиши в README секреты и пошаговые гайды «как обойти DPI в стране X».

## Скоуп правок

Меняй только то, что просит задача. Не рефактори соседние крейты. Не коммить `.env`, ключи, `*.der`, `.DS_Store`.
