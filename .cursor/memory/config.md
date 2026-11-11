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
| `PAYPHONE_EXCLUDE_FILE` | `--exclude`, toml `exclude_file`; default `payphone-exclude.json` если есть (явный путь обязан существовать). Поддерживает IPv4/CIDR и DNS names, которые разрешаются в IPv4 при старте; apex добавляет `www`. Шаблон `payphone-exclude.example.json`, сам файл в `.gitignore` |

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

## Узел 103.74.92.168 (2026-11-08)

- Ubuntu x86_64, 2 vCPU / 4 ГБ RAM. PAYPHONE отдельно от существующего Coolify-прокси; 443 занят, QUIC и TLS опубликованы на 8443. Не останавливать прокси для PAYPHONE.
- Standalone Compose: `/opt/payphone/compose.yml`, project `payphone`, container `payphone-server`, server.env 0600. Шаблон `deploy/standalone.compose.yml`. Ресурс PAYPHONE в Coolify для этого узла не создавался.
- Образ `payphone-server:0.2.0-wan-bbrfix-20261108T191645Z`, собран на VPS с --locked и vendor Quinn из whitelisted source snapshot; signing private key не загружен. Исходники/manifest `/opt/payphone/current` → releases/<release>/src; это снимок dirty working tree, не опубликованный Git release.
- Bind state/certs: `/opt/payphone/state`, `/opt/payphone/certs`; subnet /16. restart unless-stopped, SIGINT, healthcheck, log rotation, read-only rootfs; tmpfs /tmp и /run (iptables lock), NET_ADMIN/NET_BIND_SERVICE. Не удалять state/certs при обновлении.
- TLS SAN localhost,103.74.92.168; клиент server name 103.74.92.168, CA=pin. REALITY off. Новый PSK и 30-day Pro token в игнорируемом `runtime/node-103.74.92.168/client/` (client.env, subscription.token, payphone-cert.der). Не публиковать секреты.
- Проверены QUIC/TLS auth, DNS/NAT, Rekey, resume, реальный TUN/HTTPS egress 103.74.92.168, HTTP200 с проверкой cert, restart с активным клиентом/сохранённой сессией и прежним pin. Контейнер healthy; существующие приложения не перезапускались. В тестовом Docker-клиенте DNS явно задан 10.77.0.1, т.к. resolvectl отсутствует; хостовый DNS не менялся.
- Производительность 200–300 Mbps на этом VPS ещё не измерена. Подробности и управление: `docs/node-103.74.92.168.md`.
- Консольный клиент macOS arm64 пересобран 2026-11-08: target/release/payphone-client. Корневой .env локальной рабочей копии теперь содержит профиль этого узла, абсолютные пути token/pin/session и dev_mode=false; прежний .env сохранён в runtime/node-103.74.92.168/backups/<timestamp>/root.env (0600). Legacy root .payphone-session не удалять, используется отдельный session file нового узла. Portable binary+relative .env+token+pin+launcher: runtime/node-103.74.92.168/payphone-console-macos-arm64.zip (закрытые credentials, не в Git). Обновлённый профиль повторно проверен probe_vpn по QUIC/TLS без host TUN/route изменений; macOS VPN не оставлен включённым.

## Диагностика производительности

`PAYPHONE_QUIC_STATS=1` — opt-in RTT/cwnd/loss/replay-discard/datagram counters раз в секунду в Rust client/server, default off; не пишет payload, PSK или токен. Это env-only диагностика (не CLI/TOML setting). Изолированный стенд, критерии и knobs `LAB_TCP_STREAMS`, `LAB_DELAY_MS`, `LAB_TOKIO_WORKERS` — `docs/performance.md`, `tools/perf/`. Не применять tc/маршруты стенда к host/VPS.

Обновление2026-11-09: на103.74.92.168 новый BBR startup fix (cwnd вместо cwnd_gain в сравнении с target bytes), текущий image release-id в /opt/payphone/release-id.txt и runtime/node-103.74.92.168/release-id.txt. Current source manifest обновлён, прежние образы сохранены. Server PAYPHONE_QUIC_STATS=1 через server.env + optional compose env; root локальный .env также stats1 для следующего запуска. Старый Mac-процесс не заменяется переписываемым бинарником: нужен Ctrl+C и повторный sudo запуск. Kernel UDP buffers persistent defaults4MiB/max16MiB; syscall настройки на HOST, не в Docker sysctls. Все временные iperf containers/host rules5202 удалены, чужие приложения не перезапускались.

Rollback после жалобы пользователя: production103 снова image0.2.0-wan-bbrfix-20261108T191645Z (только первый startup fix). Sampling candidate0.2.0-wan-bbrsample-20261108T212601Z НЕ оставлен в production: long-lived session после перезапуска имела QUICcontrol без innerdata, причина не установлена; fresh session после rollback ping10.77.0.1/1.1.1.1PASS. Все WANiperf/candidateконтейнеры удалены. НаMac далее замечен другой VPN VPSUS, не отключать его. PublicSSH ссуществующимключом снова доступен через этот маршрут. Applebuild3 собран/подписан, установка не состоялась (deviceunavailable); последняя подтверждённая установленнаяbuild2. Дальнейшие выкладки остановлены, приоритет восстановление соединения.

2026-11-09 connection recovery: iOS App ContentView used fresh @State settings and never restored NETunnelProviderProtocol.providerConfiguration. Build4 restores server/transport/SNI/PSK/binary token/pin from this app’s saved profile, filters manager by own extension bundle, updates status on load, allows disconnect even with empty UI settings, validates required fields before overwriting saved profile. Secrets are already in existing NE preferences; no new secret store/baked config. Removed incorrect comment claiming settings secrets are stored separately in Keychain. Signed build4 installed on connected iPhone; runtime/ios/20261109-build4/Payphone-1.0-build4.ipa. For recovery, bundled entire tunnel extension from known installed build2, changed only bundle version/re-signed: PayphoneTunnel.debug.dylib SHA byte-identical to build2, recorded in tunnel-engine-sha256.txt. Plain xcodebuild would relink current native artifacts; this recovery IPA is a post-build assembly retaining the old engine. Server stays BBR firstfix191645, fresh QUIC+TLS auth/rekey/DNS/NAT/resume probes pass; physical user connection still needs verification. Mac currently VPSUS, own CLI not running, no noninteractive sudo. Do not claim all devices restored based on these probes.

Android node APK 2026-11-10: runtime/android/20261110-node1/PAYPHONE-Android-arm64-v0.2.0-node2.apk, versionCode3, package com.payphone.android, debug signed. One-tap personal build includes server/SNI103.74.92.168:8443, QUIC, pinned public DER, PSK and Pro token (BuildConfig defaults from ignored runtime/node-103.74.92.168/android-build-profile.properties). Never commit profile or distribute APK publicly: subscribers may extract credentials. APK SHA256 37bfdb7e...833d6bd2. Certificate9edf00fd...72973; apksigner v2 verified; DEX contains intended PSK/token; arm64 JNI/QUIC libraries verified. Build checked against attached TECNO CLA5 Android16 ARM64. Built only; no install requested/performed. First Jack in may show standard Android VPN consent.
