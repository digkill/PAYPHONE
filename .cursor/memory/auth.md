# Подписка и токены

Крейты `payphone-auth` + CLI `payphone-token`. `payphone-core` видит токен только как bytes.

## Формат (135 байт, фиксированный)

Magic ASCII `PAYT`, version `1`.

| Поле | Размер |
| --- | ---: |
| magic `PAYT` | 4 |
| version | 1 |
| key_id | 4 |
| token_id | 16 |
| client_id | 16 |
| issued_at | 8 |
| not_before | 8 |
| expires_at | 8 |
| plan | 1 |
| device_limit | 1 |
| max_mbps | 4 |
| Ed25519 signature | 64 |
| **итого** | **135** |

`TOKEN_PAYLOAD_SIZE = 71`. Decode ≠ verify: после разбора обязательна проверка подписи и claims.

Подпись: Ed25519 над payload (dalek v3). `key_id` выбирает ключ из `VerificationKeyRing`. Сервер сейчас грузит `auth-keys/subscription-public.key` как **key_id = 1** (тот же ID пишет `payphone-token`).

Clock skew verifier: **300s** (`CLOCK_SKEW_SECONDS`).

## Планы

| Plan | u8 | device_limit | max_mbps |
| --- | ---: | ---: | ---: |
| `basic` | 1 | 1 | 100 |
| `pro` | 2 | 5 | 500 |
| `unlimited` | 3 | 255 | 0 (без потолка) |

`255` устройств = `UNLIMITED_DEVICES` в `session.rs`. При превышении лимита вытесняется самая старая сессия этого `client_id`. Mbps: два независимых token-bucket по размеру inner IP на сессию (upload/download); каждый ограничен max_mbps. 0 = не режем. Лимит устройств по client_id; Mbps не суммируется между устройствами.

## Revoke

Файл: одна hex `token_id` (32 hex chars) на строку. Default `auth-keys/revoked-token-ids.txt` / `PAYPHONE_REVOKE_FILE`. `FileRevocationStore::open` загружает начальный снимок; сервер вызывает `refresh()` в `spawn_blocking` раз в секунду. `is_revoked` читает снимок без файловых syscall; задержка отзыва — интервал обновления плюс время чтения/планирования. До первого появления файла отсутствие означает пустой набор. Если файл исчез после загрузки, известные отзывы сохраняются в памяти; ошибки чтения запрещают доступ до успешного фонового обновления. Не вызывать `refresh()` на DATA-пути.

```bash
cargo run -p payphone-token -- revoke subscription.token
# или hex token_id
```

Срок и отзыв повторно проверяются для resume, DATA/PING/Rekey/Close и исходящего трафика; cleanup удаляет недействительные сессии, включая восстановленные с диска. `payphone-token revoke` уважает `PAYPHONE_REVOKE_FILE`.

Trait `RevocationStore` — чтобы позже подставить Redis/Postgres; сейчас файл.

## CLI `payphone-token`

| Команда | Действие |
| --- | --- |
| `init` | Ed25519 пара → `auth-keys/subscription-private.key` + `subscription-public.key` |
| `issue <days> <plan>` | токен в `subscription.token` |
| `setup <days> <plan>` | init при необходимости + issue |
| `revoke <token\|hex>` | append в revoke-файл |
| `reality-init` | X25519 + short-id в `auth-keys/reality-*.` |

Private signing key **никогда** не в образ и не клиенту. Dockerfile копирует только `subscription-public.key`. Compose локально монтирует public key read-only.

## Файлы (gitignore)

| Путь | Кто | Секрет? |
| --- | --- | --- |
| `auth-keys/subscription-private.key` | issuer | да |
| `auth-keys/subscription-public.key` | сервер (в git специально) | нет |
| `subscription.token` | клиент | да (носитель подписки) |
| `auth-keys/revoked-token-ids.txt` | сервер | нет (список id) |
| `auth-keys/reality-private.key` | сервер | да |

Не коммитить `.env`, `payphone.toml`, `*.der`, `.payphone-session`.
