# PAYPHONE — 103.74.92.168

Развёртывание от 8 ноября 2026 года. Узел: Ubuntu x86_64, AMD EPYC, 2 vCPU,
4 ГБ RAM. Работает отдельно от существующих приложений и Coolify-прокси.
Порт 443 занят прокси; PAYPHONE использует **8443/UDP** для QUIC и **8443/TCP**
для TLS. REALITY выключен. Проверка TLS — pinning сертификата, server name
`103.74.92.168`. VPN-подсеть `10.77.0.0/16`, DNS `10.77.0.1`.

## Файлы на сервере

Рабочий каталог: `/opt/payphone`. Compose project: `payphone`, контейнер:
`payphone-server`. Этот узел запущен обычным Docker Compose; ресурс приложения
PAYPHONE в Coolify для него не создавался.

- `compose.yml` — копия [standalone.compose.yml](../deploy/standalone.compose.yml).
- `server.env` — закрытая конфигурация с PSK и тегом образа; права 0600.
- `certs/` — постоянный сертификат и закрытый TLS-ключ.
- `state/` — сессии и список отзывов `revoked-token-ids.txt`.
- `releases/<release>/src/` — доставленные исходники, vendor Quinn и
  `source-sha256.json` для проверки каждого исходного файла.
- `current` — ссылка на исходники установленной сборки.
- `install.log`, `deployed-image-id.txt`, `deployed-binary-sha256.txt` —
  журнал сборки и идентификаторы установленного артефакта.

Корневой каталог доступен только root. Private subscription signing key на
сервер не передаётся: образ содержит только public verification key проекта.
Образ собирается на самом VPS из `Dockerfile.node` с `cargo build --locked`,
одним заданием компиляции и локальным патчем Quinn. Build context состоит из
разрешённого списка исходников; рабочие секреты и сертификаты в него не входят.

## Управление

По SSH на узле:

```bash
cd /opt/payphone
docker compose -p payphone --env-file server.env -f compose.yml ps
docker compose -p payphone --env-file server.env -f compose.yml logs --tail 100
docker compose -p payphone --env-file server.env -f compose.yml restart
```

Настроены restart `unless-stopped`, healthcheck TUN/обоих слушателей, ротация
логов, read-only root filesystem и отдельные writable-каталоги состояния.
Контейнер получает NET_ADMIN и NET_BIND_SERVICE, `/dev/net/tun`; forwarding
и NAT настраиваются внутри его network namespace. Хостовые маршруты VPN не
устанавливаются. Остановка отправляет SIGINT с 20-секундным grace period.

Перед обновлением сохранить закрытую копию `server.env`, `certs/` и `state/`.
Собрать новый образ с отдельным тегом, проверить его и изменить только
`PAYPHONE_IMAGE` в `server.env`, затем выполнить `up -d --wait` с теми же
параметрами Compose. Для отката вернуть предыдущий тег; актуальный список
отзывов не заменять устаревшим. Сохранённый сертификат нельзя удалять при
обычном обновлении, иначе pin клиентов перестанет совпадать.

## Клиент

Закрытый локальный каталог `runtime/node-103.74.92.168/client/` исключён из Git:
`client.env`, `subscription.token`, `payphone-cert.der`.
Новая подписка Pro выдана на 30 дней: до 5 устройств, лимит 500 Мбит/с на
направление каждой сессии. Это тарифный лимит, а не измеренная скорость VPS.

Из корня репозитория:

```bash
cargo build --locked --release -p payphone-client
set -a
source runtime/node-103.74.92.168/client/client.env
set +a
sudo -E ./target/release/payphone-client
```

Для TCP/TLS после загрузки профиля установить `PAYPHONE_TRANSPORT=tls`.
В мобильном приложении указать адрес `103.74.92.168:8443`, server name
`103.74.92.168`, импортировать token и DER pin; PSK взять из `client.env`.
Секреты не копировать в публичные отчёты и Git.

8 ноября консольный клиент пересобран для macOS arm64, корневой `.env`
локальной рабочей копии переключён на этот узел. Старая конфигурация сохранена
в закрытом `runtime/node-103.74.92.168/backups/`. Теперь из корня проекта
достаточно `sudo ./target/release/payphone-client`; файл сессии отдельный
для этого сервера. QUIC и TLS повторно проверены с обновлёнными настройками
без изменения маршрутов macOS.

Готовый переносимый комплект:
`runtime/node-103.74.92.168/payphone-console-macos-arm64.zip`.
Внутри бинарник, `.env` с относительными путями, token, DER pin и
`run-client.command`. Запускать из Terminal, остановка — Ctrl+C;
`./run-client.command --transport tls` выбирает TCP. Архив содержит закрытые
клиентские учётные данные.

Измерения локального стенда на 300 Мбит/с из [performance.md](performance.md)
не доказывают ту же скорость этого VPS через реальный интернет.

## Проверено после установки

- Контейнер `running:healthy`, forwarding/NAT и DNS stub работают.
- QUIC и TLS с настоящим сертификатным pin: авторизация, PING/PONG, Rekey,
  повторный ACK, resume через новое соединение, DNS к `10.77.0.1` и `1.1.1.1`,
  отправка IPv4-пакета 1100 байт.
- Изолированный Linux TUN-клиент на локальной машине: маршрут через payphone0,
  ICMP до интернета, HTTPS-запрос через VPN возвращает egress `103.74.92.168`.
  В тестовом контейнере резолвер явно установлен на `10.77.0.1`, поскольку
  там нет systemd-resolved/resolvectl; это не проверка DNS-настроек хостовой ОС.
- Перезапуск сервера с активным клиентом: сервер загрузил сохранённую сессию,
  клиент автоматически выполнил resume с прежним адресом `10.77.0.2`.
- SHA256 сертификата до и после перезапуска совпал:
  `9edf00fd15cf3723ee02f9c38db19690e0fe2efaddb6f8508cb7a18894e72973`.
- HTTPS front вернул HTTP 200 при включённой проверке сертификата.
- Private subscription key в runtime-образе отсутствует; существующие
  приложения и прокси продолжают работать.
- Локальный `cargo test --workspace` перед развёртыванием прошёл: 127 тестов.

Первоначальный тег: `payphone-server:0.2.0-20261108T135807Z`.
SHA256 архива исходников:
`1e736af08aa8338f53a24a9d15d81420cb96370e6d0398dd83d28e99c273a891`.
SHA256 первоначального бинарника:
`7f39856013687523ebea490cccdcbab5a8015d7178915c06ba3a1ac5d06b8bfa`.
Чистый release commit ещё не подготовлен; этот артефакт собран из проверенного
снимка рабочей копии с отдельным manifest, включая новые файлы и vendor.

Длительная нагрузка 200–300 Мбит/с и физические мобильные устройства на этом
узле ещё не проверялись. Журналы проверок находятся в закрытом локальном
`runtime/node-103.74.92.168/`, профиль пользователя — в его подкаталоге `client/`.

## Обновление 9 ноября: входящая скорость и iOS

На хосте установлен `/etc/sysctl.d/90-payphone-udp-buffers.conf`
([шаблон](../deploy/90-payphone-udp-buffers.conf)): UDP defaults 4 MiB, maxima
16 MiB. После пересоздания PAYPHONE UDP-прокси Docker перестал переполнять
прежние 212-КБ буферы. Настройка сохраняется после перезагрузки и влияет
на будущие UDP-сокеты хоста; прежние значения сохранены в
`/opt/payphone/speed-diagnosis/udp-sysctl-before.json`.

Текущий образ: `payphone-server:0.2.0-wan-bbrfix-20261108T191645Z`.
Включён BBR с исправлением startup window guard, GSO сохранён. После
исправлений контрольная загрузка активного Mac-клиента составила 63.32 Мбит/с
против 6.47 в начале проверки. Цель 200–300 Мбит/с на WAN не достигнута;
все условия и неудачные варианты сохранены в [performance.md](performance.md).

Серверная диагностика `PAYPHONE_QUIC_STATS=1` включена в `server.env` и
ограничена ротацией логов. Для следующего запуска консольного клиента
диагностика также включена в корневом `.env`. Пример записи stderr:

```bash
sudo ./target/release/payphone-client 2>>runtime/node-103.74.92.168/speed-diagnosis/mac-client-quic.log
```

Свежая iOS-сборка 1.0 (2), Rust core 0.2.0, собрана с обновлённым QUIC
и установлена на подключённый iPhone 16 Pro Max. Установочный файл:
`runtime/ios/20261109-build2/Payphone-1.0-build2.ipa`. Проверка запуска
требует разблокированного телефона; скорость на iPhone этим не измерялась.


## Восстановление подключения 9 ноября

Production оставлен на `0.2.0-wan-bbrfix-20261108T191645Z` после отката.
Последующая проверка QUIC/TLS подтвердила авторизацию, DNS через stub/NAT,
rekey и resume; это не подтверждение подключения пользователя с телефона.

В iOS найден отдельный дефект: после завершения приложения `@State`
создавал пустые настройки, а сохранённый VPN-профиль не читался. Сборка 4
восстанавливает настройки из существующего `providerConfiguration`, включая
бинарный токен и pin; пустые обязательные поля больше не перезаписывают
сохранённый профиль при подключении. Сервер и формат протокола не менялись.
Для восстановления в подписанный app build4 включена прежняя tunnel extension
из build2: `PayphoneTunnel.debug.dylib` совпадает по SHA256, изменены только
версия bundle и подпись. IPA и SHA — в закрытом `runtime/ios/20261109-build4/`.
Обычный повторный Xcode build заново свяжет текущие native artifacts; это
следует отличать от установленной recovery-сборки с прежним движком.
