# PAYPHONE — память проекта для агентов

Это **карта репозитория**, не пользовательская документация. Читай отсюда, а не восстанавливай архитектуру с нуля из `README.md` и статей.

Человеческие доки: `README.md`, `docs/habr-payphone.md`, `docs/devto-payphone.md`. При расхождении **код побеждает** README и статьи.

## Как пользоваться

1. Всегда: [`overview.md`](overview.md) + [`conventions.md`](conventions.md).
2. По задаче — один тематический файл (не тащи все сразу):

| Задача | Файл |
| --- | --- |
| Крейты, потоки данных, границы модулей | [`architecture.md`](architecture.md) |
| Кадры, handshake, resume, DATA | [`protocol.md`](protocol.md) |
| QUIC, обфускация, TLS 443, REALITY | [`transport.md`](transport.md) |
| Токены, планы, revoke, ключи | [`auth.md`](auth.md) |
| TUN, NAT, маршруты, kill-switch | [`routing.md`](routing.md) |
| Env, файлы, Docker, Coolify | [`config.md`](config.md) |
| Известные ловушки (MTU, macOS, SIGINT) | [`gotchas.md`](gotchas.md) |

Правила Cursor (короткие, с globs): `.cursor/rules/`. Точка входа репозитория: `AGENTS.md`.

## Когда обновлять эту папку

Меняешь протокол, порты, env, MTU, транспорт или инварианты безопасности — поправь соответствующий файл **в том же изменении**. Не копируй секреты. Не описывай эксплойты — только как устроен свой код.
