# Ловушки (уже жгли прод и Mac)

Подробный рассказ: `docs/habr-payphone.md`. Здесь — чеклист, чтобы не повторить.

## MTU / Quinn

- QUIC packet MTU сейчас фиксирован на 1200, PMTUD выключен: обёртка добавляет ещё 10–42 bytes после sizing Quinn. Проба с коротким pad не доказывает, что длинный pad влезет. У Quinn остаётся собственный overhead; бюджет DATAGRAM брать из max_datagram_size, не из 1200 напрямую.
- PAYPHONE header 40 байт. TUN **1100** влезает (1140). TUN **1280** → кадр 1320 → `TooLarge` на первом «толстом» пакете.
- Регрессионный тест: `max_size_frame_sends_immediately_after_handshake` в `payphone-transport`.

## Padding buckets

Округление wire-length до `[128, 296, 568, 1200, 1440]` раздувало **PMTU-пробы** Quinn. Проба пропадала, оценка MTU падала, честный кадр не влезал. Сейчас хвост 0–32. Бакеты не возвращать. README может ещё упоминать `PADDING_BUCKETS` — **код** (равномерный pad) важнее.

## `send_datagram_wait`

Сериализовал TUN-read за отправкой: под нагрузкой входящее не крутилось. Только `send_datagram`; `TooLarge` → дроп кадра (`false`), не panic.

## macOS routing

- `networksetup` пересобирает таблицу → пропадает host-route к VPS → `/1` заглатывает сервер → QUIC в свой utun → смерть сессии.
- Маршрут `-ifscope en0` не виден unscoped lookup Quinn. Нужен обычный `/32` через LAN gateway.
- Watchdog `sleep` **внутри** `select` сбрасывался каждым TUN-пакетом и **никогда** не чинил обход под трафиком. Отдельный interval ~400ms. OS-команды выполнять в spawn_blocking (не блокировать TUN), максимум одна задача; teardown синхронизировать с ней и вызвать до закрытия QUIC, даже если worker ещё держит Arc.
- `IP_BOUND_IF` на UDP, чтобы пакеты физически шли в Wi-Fi.

## SIGINT

Tokio перехватывает Ctrl+C. Если сначала `wait_idle()`, а `/1` ещё в utun — интернет мёртв, второй сигнал никто не слушает. Сначала routing teardown, потом короткий idle.

## Linux один хост

Оба процесса хотят `payphone0`. Демо «server+client на одной Linux-машине» без netns не взлетит. macOS с `utunN` — да.

## Coolify / 443

- UI port mapping часто **только TCP**; UDP 40404 «exposed, но не published». Только `docker-compose.server.yml` с `443:40404/udp`.
- Traefik на хосте уже держит 443/tcp и 443/udp — PAYPHONE туда не встанет, пока прокси не убрать.
- Self-signed на volume `payphone-certs`: pin клиента живёт между редеплоями. Снёс volume — новый hex в логе.
- `PAYPHONE_DEV_MODE` на обоих концах, когда непонятно: пакеты не доходят vs доходят и режутся обфускацией.

## REALITY

- Без dest+ключей 443 должен остаться лендингом, не чёрной дырой splice.
- Свой hostname (`PAYPHONE_TLS_DOMAIN`) не должен уезжать на dest — иначе ACME и сайт умрут.
- EncryptedExtensions dest в plaintext не скопировать. JA3S — ServerHello dest + патч key_share.
- ClientHello «как Chrome 131», не захват живого Chrome (GREASE/ECH/KEM каждый раз другие; Chrome дрейфует).

## Матрица в терминале

`payphone-client/src/matrix.rs`: только полуширинная катакана. Полноширинная = 2 колонки при `\r` на 1 — в дождь вклеиваются счётчики пакетов.

## Прочее

- Sequence window 65536: не делать `seq <= last` reject — datagrams реально reorder.
- DoH браузера обходит DNS stub, но едет по туннелю — это ок.
- Resume после рестарта сервера: файл store должен быть на volume, не в эфемерном контейнере.

## Очередь Linux TUN под нагрузкой

При 300 Mbps ~1KiB packets дефолтные 500 packets дают ~14ms запаса. В Docker наблюдались большие всплески и TUN TX drops при нулевых UDP socket drops. TX queue теперь 8192 (ограничена, ~220ms для таких пакетов); проверять ip -s link и loaded RTT, не только средний iperf. Результаты, включая неудачные конфигурации, — docs/performance.md.

## Внутренние потери QUIC на широком канале

Upstream quinn-proto129-PN replay window отвергал поздние валидные пакеты после нескольких миллисекунд перестановки при300Mbps. В проекте локальный2048-PN ring patch (vendor/quinn-proto/PATCHES.md), BBR с исправлениями startup guard и bandwidth sampling, packet_threshold2048, time_threshold2.0 и PP sequence tolerance65536. Не возвращать registry dependency без эквивалентного исправления и нагрузочной проверки. Одних UDP socket/TUN drop counters недостаточно — внутренние отбрасывания могут не отражаться в них.

## Docker UDP proxy на реальном VPS

Ошибка входящей скорости может быть вне QUIC socket: docker-proxy host socket default212KB переполнялся (ss -uanmp skmem d923), контейнерный /proc/net/snmp при этом errors0. Увеличение receive/send очередей Quinn не меняет эти sockets. На103.74.92.168 применён deploy/90-payphone-udp-buffers.conf на HOST: defaults4MiB/max16MiB, затем пересоздан только PAYPHONE. Не рестартовать Docker daemon/чужие сервисы. Счётчик потерь cumulative; сравнивать до/после и конкретный socket.
