# Конфиг, файлы, деплой

Приоритет: **CLI > env (`.env`) > `payphone.toml` > дефолты**. `dotenvy` из CWD. Пути относительны к текущей рабочей директории — команды с корня репо.

Шаблон env: `.env.example`. Секреты в git не класть (см. `.gitignore`).

## Обязательное

| Переменная | Кто | Заметка |
| --- | --- | --- |
| `PAYPHONE_OBFS_PSK` | оба | ≥16 символов, не placeholder из example. `openssl rand -hex 32` |

## Сервер

| Переменная | Default / смысл |
| --- | --- |
| `PAYPHONE_BIND_ADDR` | `127.0.0.1:40404` (в Docker Compose форсируют `0.0.0.0:40404`) |
| `PAYPHONE_TCP_BIND_ADDR` | IP bind + `:40443`; `off` = без TCP |
| `PAYPHONE_AUTH_KEY` | `auth-keys/subscription-public.key` |
| `PAYPHONE_REVOKE_FILE` | `auth-keys/revoked-token-ids.txt` |
| `PAYPHONE_SESSION_STORE` | `./payphone-sessions.bin`; Docker `/app/state/sessions.bin` |
| `PAYPHONE_DNS_UPSTREAM` | `1.1.1.1:53` |
| `PAYPHONE_TLS_CERT` / `TLS_KEY` | PEM/DER; иначе self-signed в `dev-certs/` |
| `PAYPHONE_TLS_SAN` | SAN для генерируемого cert |
| `PAYPHONE_TLS_DOMAIN` | Let's Encrypt ALPN-01 |
| `PAYPHONE_ACME_EMAIL` / `ACME_DIR` / `ACME_STAGING` | ACME |
| `PAYPHONE_REALITY` | `off` / `on` |
| `PAYPHONE_REALITY_DEST` | например `www.microsoft.com:443` |
| `PAYPHONE_REALITY_PRIVATE_KEY` / `SHORT_ID` | после `reality-init` |
| `PAYPHONE_DEV_MODE` | `false` |
| `PAYPHONE_CONFIG` | путь к toml |

## Клиент

| Переменная | Default / смысл |
| --- | --- |
| `PAYPHONE_SERVER_ADDR` | `127.0.0.1:40404` |
| `PAYPHONE_TRANSPORT` | `quic` или `tls` |
| `PAYPHONE_TCP_SERVER_ADDR` | если TCP не на том же host:port; при UDP `:40404` → TCP `:40443` |
| `PAYPHONE_SERVER_NAME` | SNI; иначе hostname из server addr |
| `PAYPHONE_TLS_PIN` | `dev-certs/payphone-cert.der` |
| `PAYPHONE_TLS_CA` | `pin` или `system` (публичное имя ⇒ system) |
| `PAYPHONE_TOKEN` | `subscription.token` |
| `PAYPHONE_SESSION_FILE` | `.payphone-session` |
| `PAYPHONE_REALITY_PUBLIC_KEY` / `SHORT_ID` / `SNI` | только tls-транспорт |
| `PAYPHONE_KILL_SWITCH` | `false` |

## Resume-файл клиента

Magic `PAYE`, version 1, ChaCha20-Poly1305. Ключ: `SHA256("payphone-session-v1" \|\| psk)`. Старый plaintext 48 байт принимается один раз и переписывается зашифрованным.

## Session store сервера

Magic `PAYS`, version 1, record 206 байт. Переживает рестарт процесса/контейнера.

## Docker

- `Dockerfile`: multi-stage `server` / `client` / `token`. Базы — public ECR (`rust:slim-bookworm`, `debian:bookworm-slim`), не Docker Hub (429 с VPS).
- `docker-compose.yml`: local server+client; UDP 40404, TCP 40443; volumes certs, public key, token, session.
- `docker-compose.server.yml`: **прод / Coolify**. Хост `${PAYPHONE_HOST_PORT:-443}` → `40404/udp` и `40443/tcp`. Env задаёт платформа, не файл. **Не** публиковать PAYPHONE 443 рядом с Traefik на 443. UDP в UI Coolify часто ломается — только native compose `ports:` с `/udp`.

После первого self-signed деплоя скопировать hex листового сертификата из лога сервера в `dev-certs/payphone-cert.der` у клиента (если нет публичного имени).

## Быстрый локальный цикл

```bash
cargo build --workspace
cargo run -p payphone-token -- setup 30 pro
sudo ./target/debug/payphone-server --bind 0.0.0.0:40404
sudo ./target/debug/payphone-client --server 127.0.0.1:40404
cargo test --workspace
cargo fmt --all -- --check
```

## Развёрнутый узел Model Daler

- `89.40.233.36:8443`, UDP QUIC и TCP TLS; управляемый custom Service Coolify `payphone-model-daler` в PAYPHONE/production.
- Центр управления `212.8.229.215:8000`; resource UUID `zjustdvzh2jmbf9t30v69hlq`, server UUID `qr8fabzpzh4odcb5v80sw8ug`. Контейнер `payphone-server-zjustdvzh2jmbf9t30v69hlq`.
- Compose: `deploy/model-daler.coolify.yml`. PSK в Coolify; локальный образ `payphone-model-daler:0.2.0`, pull_policy never. Обновление: собрать из `/opt/payphone`, затем Restart через Coolify. Git-автодеплой не настроен.
- Существующие данные скопированы в managed volumes `<service_uuid>_certificates` и `<service_uuid>_session-state`; сертификат и PSK прежние. Coolify 4.3.3 переименовывает external volumes для custom Service.
- Старый контейнер `payphone-payphone-server-1` остановлен, restart=no; backup `/opt/payphone/backups/before-coolify/`. Не запускать прежний Compose параллельно; актуальные сессии/отзывы теперь в managed volume.
- 443 занят существующим Traefik; его конфигурацию не меняли.
- TLS SAN: `localhost,89.40.233.36`; клиентский server name **89.40.233.36**, CA mode `pin`.
- Закрытый ключ подписок остался локально. Узел проверяет подписки существующим public key проекта.
- Локальные секреты и профиль: игнорируемый `runtime/model-daler/`; не переносить в git или Docker context.
- Инструкция: `docs/model-daler.md`. Проверены QUIC/TLS, DNS/NAT, Rekey, resume после Restart через Coolify MCP, сохранение отзыва подписки при миграции и рестарте.

После MCP Restart статус Coolify может отставать от фактического Docker healthcheck. Штатная проверка в UI вызывает `App\Actions\Docker\GetContainersStatus` для нужного сервера; финальный статус узла подтверждён через MCP как `running:healthy`.
