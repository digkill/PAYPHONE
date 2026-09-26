# Model Daler — узел PAYPHONE

Развёрнут 27 сентября 2026 года. Адрес **89.40.233.36:8443** для QUIC/UDP и TLS/TCP. Порт 443 занят существующим Traefik; он продолжает работать.

Управление перенесено в центральный Coolify: **PAYPHONE → production → payphone-model-daler**.

[Открыть ресурс в Coolify](http://212.8.229.215:8000/project/nqmlfkqbggdroyz2etudgbbg/environment/x4up2pjrzcqcoay3uwhmygeb/service/zjustdvzh2jmbf9t30v69hlq)

Контейнер `payphone-server-zjustdvzh2jmbf9t30v69hlq`, образ `payphone-model-daler:0.2.0`. Настроены `restart: unless-stopped`, healthcheck TUN/UDP/TCP и ротация логов. Compose и секрет PSK хранятся в Coolify. Исходники для сборки остаются на узле в `/opt/payphone`. Данные перенесены в volumes `zjustdvzh2jmbf9t30v69hlq_certificates` и `zjustdvzh2jmbf9t30v69hlq_session-state`; сертификат и PSK не изменились. TUN: `10.77.0.1/24`, начальный MTU 1100, DNS `10.77.0.1`, upstream `1.1.1.1:53`. REALITY выключен.

## Подключение

Локальный каталог `runtime/model-daler/` исключён из Git:

- `client.env` — готовые настройки Rust-клиента, включая PSK и абсолютные пути;
- `subscription.token` — новая подписка Pro на 30 дней, до пяти устройств;
- `payphone-cert.der` — публичный сертификат для pinning;
- `server.env` — параметры узла с PSK; не публиковать.

Сервер проверяет подписки существующим публичным ключом проекта. Закрытый ключ выпуска подписок хранится только локально в `auth-keys/` и не передавался на сервер.

Из корня проекта:

```bash
cargo build -p payphone-client
set -a
source runtime/model-daler/client.env
set +a
sudo -E ./target/debug/payphone-client
```

Для TLS перед запуском: `export PAYPHONE_TRANSPORT=tls`.

Для мобильных приложений: сервер `89.40.233.36:8443`, транспорт TLS, TLS server name `89.40.233.36`; импортировать token и DER из указанного каталога, PSK взять из `client.env`. Секреты не вставлять в публичные отчёты.

Сертификат содержит SAN `localhost` и `89.40.233.36`. Для удалённого соединения использовать IP как server name: тестовый сетевой путь обрывал рукопожатие с SNI `localhost`. Проверка сертификата не отключена.

## Проверка без изменения маршрутов компьютера

После загрузки `client.env`:

```bash
cargo run -p payphone-transport --example probe_vpn
```

Проверка создаёт временные VPN-сессии, выполняет авторизацию, PING/PONG, Rekey и повторный ACK, отправляет DNS-пакеты к `10.77.0.1` и `1.1.1.1`, отправляет IPv4-пакет 1100 байт и восстанавливает сессию через новое TLS-соединение. Не создаёт локальный TUN.

На узле успешно проверены оба транспорта, выход DNS через NAT, сохранение сессии после перезапуска контейнера и отзыв отдельной тестовой подписки. Отзыв блокировал активную сессию, resume и новый handshake. Рабочая подписка `runtime/model-daler/subscription.token` не отозвана.

## Централизованное обслуживание

Запуск, остановка, перезапуск, логи, состояние, Compose и Environment Variables доступны в ресурсе Coolify по ссылке выше. VPN остаётся на Model Daler (`89.40.233.36`); центральный сервер `212.8.229.215` управляет им по SSH.

MCP endpoint: `http://212.8.229.215:8000/mcp`. При работе агента запросы передавались через SSH-туннель. MCP использован для проверки инфраструктуры и команды `control/start`; создание ресурса и настройка Compose/секрета — через штатный REST API той же установки, поскольку MCP не содержит этих операций.

Идентификаторы для MCP:

- service: `zjustdvzh2jmbf9t30v69hlq`;
- service application: `njouqv3mwoczggqi3b6kfluj`;
- server Model Daler: `qr8fabzpzh4odcb5v80sw8ug`;
- project PAYPHONE: `nqmlfkqbggdroyz2etudgbbg`;
- environment production: `x4up2pjrzcqcoay3uwhmygeb`.

Пример команды MCP:

```json
{"name":"control","arguments":{"resource":"service","action":"restart","uuid":"zjustdvzh2jmbf9t30v69hlq"}}
```

Исходный Compose для этого ресурса: [`deploy/model-daler.coolify.yml`](../deploy/model-daler.coolify.yml). Порты опубликованы напрямую: QUIC и TLS не проходят через Traefik.

### Обновление сборки

Образ собран локально на Model Daler и имеет `pull_policy: never`. Git-автодеплой и публикация образа в registry не настраивались: текущие доработки ещё не опубликованы в Git. После доставки проверенных исходников в `/opt/payphone` собрать образ:

```bash
cd /opt/payphone
docker compose -p payphone -f docker-compose.server.yml -f compose.node.yml build payphone-server
```

Затем выполнить **Restart** в ресурсе Coolify. Не запускать старый Compose через `up`: порт 8443 уже принадлежит управляемому ресурсу.

### Данные и откат

Список отзывов внутри контейнера: `/app/state/revoked-token-ids.txt`, одна hex-строка token_id на запись. Резервировать вместе с `sessions.bin` и volume сертификатов.

Перед миграцией создана закрытая копия `/opt/payphone/backups/before-coolify/`. Старый контейнер `payphone-payphone-server-1` сохранён остановленным, его автоматический запуск отключён; прежние volumes сохранены для отката. При возврате после работы нового узла сначала остановить ресурс в Coolify и перенести актуальные сессии/отзывы обратно, чтобы не восстановить устаревший список отзывов.

Установленный Coolify 4.3.3 при разборе custom Service переименовывает даже `external` volumes. Поэтому данные скопированы в штатные volumes Coolify перед первым запуском. Не заменять их пустыми хранилищами при обновлении.

После миграции ресурс имеет статус `running:healthy`; проверены оба транспорта, DNS/NAT, Rekey и resume. Дополнительно выполнен Restart через MCP: клиент восстановил сохранённую сессию, а ранее отозванная подписка осталась заблокированной. Сертификат побайтно совпадает с прежним, список отзывов перенесён. Существующие Traefik, Sentinel и старое приложение PAYPHONE на TimeWeb не менялись.

Домен, публичный CA-сертификат и испытание VPN на физических iOS/Android-устройствах в эту проверку не входили. Подключение готово по IP с pinning.

## Сборки и регрессионные проверки

В рамках доработки исправлены таймер PING, обновление активности по DATA, отзыв активных/восстановленных сессий, повторные ACK Rekey, блокировка общей обработки полной TLS-очередью и проверка IPv4. Мобильные клиенты сохраняют новый resume nonce, закрывают TLS при отмене и завершают VPN при потере соединения.

- `cargo test --workspace`: 106 тестов, все прошли.
- `cargo build --workspace`, `cargo fmt --all -- --check`: успешно.
- PayphoneKit: 23 теста; Apple app + Network Extension собраны для macOS без подписи.
- Android: 5 тестов и `assembleDebug` успешны. APK: `payphone-android/app/build/outputs/apk/debug/app-debug.apk`.

Проверка не включала длительную нагрузку и работу на физических мобильных устройствах.
