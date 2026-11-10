# Транспорт

Крейт `payphone-transport`. Клиент выбирает `PAYPHONE_TRANSPORT=quic` (default) или `tls` (алиасы: `udp`, `https`, `tcp`).

## UDP / QUIC (основной путь)

- Quinn >=0.11.12, quinn-proto 0.11.19 локально закреплён через `[patch.crates-io]` → `vendor/quinn-proto`, quinn-udp 0.5.16 в lockfile; rustls-ring, TLS 1.3. Datagrams, не streams. Старый proto 0.11.17 падает при переполнении исходящей очереди (GHSA-ppcp-v39w-8jq2); regression `outgoing_queue_saturation_does_not_panic` обязателен.
- Обфускация **каждого** UDP datagram до сокета (`obfuscation.rs` + `ObfuscatedSocket`).
- На Linux: GSO/GRO в `ObfuscatedSocket`; Quinn `enable_segmentation_offload(true)`.
- `vpn_transport_config()`: BBR с локальными правками startup growth guard и bandwidth sampling, idle 180s, keepalive 3s, initial RTT 50ms, datagram receive/send buffers по 16 MiB; ACK каждые 2 ack-eliciting пакета, max_ack_delay 1ms, packet_threshold 2048, time_threshold 2.0 (time-based loss detection включён). QUIC initial/min MTU 1200, discovery выключен: внешний ObfuscatedSocket добавляет 10–42 bytes после sizing Quinn, поэтому случайно короткий pad PMTU-пробы давал небезопасный бюджет для следующего длинного pad. На проводе максимум 1242 bytes UDP payload при QUIC packet 1200.

Неверная PSK: datagram не деобфусцируется → **тишина**, Quinn не видит handshake. Это защита от слепого active probe.

### Обфускация (не шифр)

Стиль Hysteria2 Salamander. Конфиденциальность уже у QUIC TLS.

```text
[ 8 B salt ][ XOR( tiled SHA256(SHA256(psk) || salt),  [u16 BE length][payload][pad 0–32] ) ]
```

- PSK: SHA256 → 32-byte key. Одинаковый на клиенте и сервере.
- `validate_passphrase`: минимум 16 символов; запрещён placeholder `change-me-to-a-real-random-secret`.
- Padding **равномерный 0–32 байта**. **Не возвращать бакеты** `[128, 296, 568, 1200, 1440]` — они ломали PMTU Quinn (проба 1200 прыгала в 1440).
- `PAYPHONE_DEV_MODE=true`: лог raw UDP до обфускации. По умолчанию `false` (тишина к чужому трафику — часть модели).

Обфускация **не** прячет: один долгоживущий 4-tuple, кластеризацию размеров QUIC, «сервер отвечает не всем», нестандартный порт если слушать не 443.

## TCP / HTTPS front

Порт контейнера `40443` (хост часто 443). ALPN `http/1.1`.

- Браузер / probe `GET` → маленькая лендинг-страница (`https_front.rs`, «Follow the white rabbit.»).
- PAYPHONE-клиент после TLS пишет те же кадры length-prefixed.
- UDP obfuscation **не** применяется.
- Серверная очередь TLS использует `try_send`: при заполнении отбрасывает новый кадр, не блокируя общий TUN-loop. Управляющие кадры тоже могут быть потеряны; handshake ограничен тайм-аутом.
- Мобильные TLS read/send/connect закрывают соединение при отмене; после тайм-аута resume создаётся новый stream. Пустой pin в Apple означает системное доверие. Android проверяет hostname при системном CA.
- `PAYPHONE_TCP_BIND_ADDR=off` выключает TCP. Иначе default: IP UDP-bind + порт 40443.
- Клиент: если UDP порт 40404 и `PAYPHONE_TCP_SERVER_ADDR` не задан — TCP цель автоматически `:40443`.

## TLS identity

Сервер (`identity.rs` / `tls.rs`):

1. Self-signed `dev-certs/payphone-cert.der` + `payphone-key.der`, SNI по умолчанию `localhost`. Клиент пинит leaf (`PAYPHONE_TLS_PIN`).
2. PEM/DER `--tls-cert` / `--tls-key` (`PAYPHONE_TLS_CERT` / `PAYPHONE_TLS_KEY`), reload по mtime.
3. Let's Encrypt: `PAYPHONE_TLS_DOMAIN`, TLS-ALPN-01 на том же TCP 443. Кэш ACME: `PAYPHONE_ACME_DIR` (в Docker `/app/state/acme`). Staging: `PAYPHONE_ACME_STAGING`.

Клиент: публичное DNS-имя в `--server` ⇒ SNI = hostname и `--tls-ca system` (WebPKI), pin не обязателен. Явный `PAYPHONE_TLS_CA=pin` оставляет pin.

## REALITY (опционально, только TCP)

Default **off**. `PAYPHONE_REALITY=on` + dest + X25519 + shortId. Inner = PAYPHONE, не VLESS. Xray-клиент с теми же ключами пройдёт outer handshake и упрётся в чужие кадры.

Схема как у XTLS/Xray:

- **Outer:** ClientHello `session_id` = X25519 + HKDF-SHA256 `"REALITY"` + AES-256-GCM. Версия в session_id: `CLIENT_VERSION = [0, 2, 0]`.
- Не авторизованный hello → **TCP splice** на `PAYPHONE_REALITY_DEST` (живой TLS 1.3 сайт с VPS).
- Авторизованный → ephemeral Ed25519 cert, подпись **HMAC-SHA512(AuthKey, pubkey)** (проверка как Xray `VerifyPeerCertificate`). Клиенту pin не нужен; SNI dest: `--reality-sni`.
- Если задан `PAYPHONE_TLS_DOMAIN`: ClientHello на **это** имя → свой лендинг + ACME; остальные → splice/REALITY.

ClientHello: форма **Chrome 131** (GREASE края, shuffle середины, GREASE ECH, ALPN `h2`+`http/1.1`, X25519MLKEM768 + X25519). Hybrid share несёт настоящий ML-KEM-768 public; VPN завершается на **X25519**. Свой TLS 1.3 stack (`reality/tls13.rs`), чтобы CertificateVerify мог быть Ed25519 HMAC (Chrome не рекламирует ed25519 в `signature_algorithms`). Не бит-в-бит дамп живого Chrome.

ServerHello после auth: копия dest, патч только X25519 `key_share` (JA3S dest). Suites: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305. Dest мёртв → свой ServerHello.

Encrypted record sizes: как у dest (handshake + post-handshake `0x17` из трёх фоновых проб ALPN none / http/1.1 / h2). **Не копировать plaintext EncryptedExtensions dest** — он внутри AEAD, ключей dest нет; эхоим ALPN клиента.

Ключи: `payphone-token reality-init` → `auth-keys/reality-private.key`, `reality-public.key`, `reality-short-id.txt`.

Не включать REALITY в Coolify, пока dest и ключи не лежат рядом с деплоем.

## Мобильный QUIC

`payphone-mobile`: общий C ABI с Quinn + существующим ObfuscatedSocket. `pp_open` принимает 32-byte SHA256(PSK) и DER pin (пустой = WebPKI roots), создаёт endpoint без подключения. Android обязан вызвать VpnService.protect(pp_socket_fd) ДО pp_connect. Apple исключает фактический IPv4 endpoint из маршрутов по pp_remote_ipv4. `pp_send` — неблокирующий send_vpn_datagram; `pp_receive` — poll 50ms; close закрывает endpoint и будит читателей. Handle registry хранит Arc, конкурентный close не освобождает объект под read/send.

JNI библиотеки собираются `payphone-android/native/build.sh [aarch64-linux-android|x86_64-linux-android]`, затем Gradle. Apple: `payphone-apple/build-native.sh`, затем SPM/Xcode; XCFramework условно подключается в Package.swift. Без сгенерированных библиотек TLS работает; выбор QUIC явно сообщает об отсутствии native. Проверка UDP roundtrip C ABI входит в cargo test. Физические устройства требуют отдельного прогона.

## Горячий путь 200–300 Мбит/с

`send_vpn_datagram` делает один `send_datagram`: проверку TooLarge выполняет Quinn под своим lock; отдельный max_datagram_size перед каждой отправкой удваивает contention. Для расчёта MTU интерфейса API max_datagram_size по-прежнему нужен.

`ObfuscatedSocket` переиспользует thread-local transmit Vec (fallback локальный Vec при reentrant try_send). GSO добавляет сегменты прямо в общий буфер; salt 8 + length 2 + padding 0–32 остаются прежними. Приём расшифровывается в UDP-буфере и компактируется copy_within, без Vec на пакет. RecvMeta допускает равные plain strides и один более короткий последний. При другом сочетании длин сохранять все datagrams: редко используемая pending-очередь удерживает максимум один kernel receive batch, Bytes slices делят одну копию смешанного GRO-буфера. После первого mixed batch последующие iovec тоже ставятся в очередь, чтобы не переставлять пакеты за пределы replay window Quinn; pending полностью дренируется до следующего inner.poll_recv. Нормальный равномерный GRO не выделяет память на пакет. Старый fallback отбрасывал всё после первого пакета — не возвращать. Регрессии проверяют короткий средний сегмент, два mixed iovec и последующий uniform GRO с частичным дренированием, порядок и отсутствие потерь. Декодирование также проверено прежним allocating-декодером.

Benchmark по умолчанию собирает новый DATA frame на каждый IP-пакет. PAYPHONE_BENCH_REUSE_FRAME=1 — старый template-only режим для сравнения. Печатает секундные окна, минимум после 3s прогрева, frame_tx, queue/receive drops. Опциональные PAYPHONE_BENCH_MIN_MBPS и PAYPHONE_BENCH_MAX_LOSS_PCT возвращают ненулевой exit при нарушении. Результаты и границы проверки — docs/performance.md.

Нормальный Rust TUN DATA сначала пытается enqueue (bool у ClientLink::send). max_datagram_size/ip_mtu и IPv4 fragmentation/ICMP нужны только после неуспешной попытки; при queue drop и подходящем MTU пакет не посылается повторно. Контрольные send bool можно игнорировать как прежде. Исходящая datagram queue 16 MiB — ограниченный запас на временные паузы при 300 Mbps, не предвыделенная память; на большом числе занятых сессий учитывать суммарную память/задержку.

Локальная проверка одного подключения: tools/perf/check-local.sh (цель 300, минимум каждого секундного окна после прогрева 200, недоставка ≤0.1%). Tokio workers не переопределяются скриптом. Linux TUN/NAT lab tools/perf/run.sh изолирован в Docker; LAB_TOKIO_WORKERS задаёт workers отдельно клиенту и серверу (в измерениях 2). Не переносить loopback-показатели на WAN. Проверки и результаты — docs/performance.md.

Android/Apple QUIC-приём переиспользует один 65535-byte scratch buffer на канал с сериализацией receive (Kotlin Mutex / Swift serial DispatchQueue); копируется только фактический кадр. Нельзя снова выделять 64 KiB для каждого DATA. Физические устройства отдельно проверять нагрузкой.

PAYPHONE_QUIC_STATS=1 включает opt-in диагностику connection stats раз в секунду у Rust клиента/сервера (RTT/min RTT, cwnd, lost/sent, dup_discard, DATAGRAM TX/RX, free queue); для mixed GRO отмечает сохранённые datagrams. По умолчанию выключено, без dump payload/PSK. Lab включает её для диагностики.

Критерий пользователя — сумма трафика одной VPN-сессии, а не один TCP-поток. LAB_TCP_STREAMS=8 создаёт восемь TCP streams внутри того же VPN; общий target делится на stream count, UDP target остаётся общим. LAB_DELAY_MS применяется ДО handshake через tc filter только к outer QUIC UDP (по 25ms egress клиенту/серверу → RTT ~50ms до сервера и ближнего NAT peer); NAT-leg не задерживается. LAB_WARMUP_SECONDS задаёт явный прогрев, LAB_TCP_ONLY=1 запускает только двусторонний TCP с тем же teardown/report gate. Отдельный эксперимент с резким добавлением задержки после loopback-handshake выявил плохое восстановление BBR; не выдавать static-path тест за проверку roaming/скачков RTT. Ноябрьский лабораторный профиль использовал CUBIC/GSO; текущий WAN-профиль использует BBR с исправленным startup guard и GSO. Старые результаты не характеризуют новую конфигурацию.

## Окно QUIC для широкополосного DATAGRAM

Vendored quinn-proto 0.11.19 меняет пять файлов: spaces.rs (окно), stats.rs и connection/mod.rs (счётчик discarded_duplicate_packets), congestion/bbr/mod.rs (startup cwnd guard + controller regression), congestion/bbr/bw_estimation.rs (bandwidth sampling). Окно: replay horizon 129 → 2048 authenticated packet numbers, 256-byte ring bitmap, +240 bytes bitmap storage на packet-number space (struct padding зависит от target). Обычный insert O(1), очистка скачка/поиск missing — по словам, максимум32. Уже принятые и вышедшие за окно пакеты по-прежнему отвергаются. Временная трассировка показала сотни внутренних dedup drops на пути с задержкой; после расширения в коротком сравнительном прогоне их не было. Трассировщик с привязкой к upstream line number удалён; PAYPHONE_QUIC_STATS выводит dup_discard из нового счётчика; это также compile-time проверка выбора локальной зависимости. Регрессия с реальным дублированным encrypted datagram проверяет счётчик и однократную доставку payload.

Источник/лицензии/SHA256/точный diff — vendor/quinn-proto/PATCHES.md и replay-window.patch. Upstream library tests320 (включая oracle, wraps/gaps, старейший бит и поздний пакет >129) проходят отдельно от127 workspace tests. Команда из корня: CARGO_TARGET_DIR="$PWD/target" cargo test --manifest-path vendor/quinn-proto/Cargo.toml --lib. При обновлении Quinn сохранить/rebase исправление и повторить тесты. Docker/native builds используют --locked, vendor входит в build context. Обновлять оба конца: поведение receiver-side, wire/capabilities/ABI прежние.

Server PAYPHONE sequence tolerance65536 покрывает2048 QUIC packets с несколькими DATA на пакет (до18 минимальных IPv4 DATA в текущем бюджете). Это отдельный coarse stale-frame guard; точные дубли в нём и раньше проходили, криптографическая replay-защита у QUIC/TLS.

Финальная Linux TUN/NAT проверка runtime/perf-lab.sdjtv8/results: outer RTT~50ms,8 TCP streams/1 VPN,30s warmup+120s measured,300M total/направление,2 workers/процесс,CUBIC/GSO/watchdog ON. TCP receiver avg300.04/299.90,min1s273.67/275.66,по119 windows; UDP30s/направление после3s warmup avg300/300,min298.59/270.50,loss0%. Full report/route repair/SIGINT PASS. Loaded ping avg58.98,max495.89ms: throughput не гарантирует низкую latency. Предыдущий тот же профиль Dkwbje не прошёл coverage117<119 из-за iperf timer jitter, пороги при повторе не менялись. Локальные2min не доказывают физический WAN/VPS/phone capacity.

WAN 2026-11-08/09: VPS103.74.92.168 / native macOS console показал6.47Mbps download/155.49upload. Docker host UDP proxy имел212992-byte buffers и923drops на connected socket, при0errors в контейнере. /etc/sysctl.d/90-payphone-udp-buffers.conf задаёт defaults4MiB,max16MiB; пересоздание только PAYPHONE даёт proxy4MiB/drops0. BBRunmodified+buffers59.01, CUBIC+buffers41.14 (4MiB TCPwindows45.58), BBRсstartupfix63.32Mbps. Это25–30s раздельные замеры, не200–300WAN acceptance; Mac-клиент в этих замерах был старым CUBIC до пользовательского перезапуска. DirectTCP8flows183.63; directUDP100M99.94/loss0,200M166.61/loss16.61%. GSOoff11.95, откатили.

BBR startup correction: self.cwnd_gain < target_window as f32 было ошибочным сравнением gain с bytes; теперь self.cwnd < target_window. App-limited startup больше не наращивает cwnd после достижения model target; регрессия проверяет предел, постепенный рост и отсутствие shrink в startup. Патч не устраняет ProbeRTT/смену minRTT и не доказывает congestion fairness. Дополнительно исправлен bandwidth filter: положительный app-limited sample допускается, если повышает estimate; любые положительные non-limited samples продвигают expiry старого пика. Без этого estimate оставался0 с app-limited birth, а ACK aggregation снова раздувал target/cwnd (на WAN наблюдалось185MB). Quinn PR2798 описывает обе связанные ошибки. Точный diff5files в vendor PATCHES/replay-window.patch,320upstreamtests; новые тесты: seeding/no-lower limited, peak expiry,100paced rounds bounded cwnd. WAN validation этой второй правки записывается отдельно в docs/performance.md; не считать старые63.32 её результатом.

Текущий BBRstartupfixed/GSO повторно прошёл TUN/NATlab runtime/perf-lab.XRhgpO/results (RTT50ms,8flows,10s warm+30sTCP,UDP10s each+3s warm). TCPmin1s294.73UL/293.97DL,UDPmin292.01/299.16,loss0%,report/routeRepair/SIGINT PASS. Это короткий30s лабораторный прогон, неWAN200–300 acceptance; WANactiveMacполучил63.32.

Apple native все5targets пересобраны, Swift23tests; подписанныйiOSapp1.0(build2) установленнаwiredpairedDigkill iPhone16ProMax00008140-001611511ADB001C. Rustcore0.2.0включаетBBRstartupfix; nativepp_symbols проверенывPayphoneTunnel.debug.dylib (основнойappex executable—debug shim). Deviceapps metadata bundleVersion2. УстройствоLocked отклонилоавтозапуск; OSunlock не обходить. IPA runtime/ios/20261109-build2/Payphone-1.0-build2.ipa, appprofilesecretsвбинарникнепомещались.

После этой правки обновлены server/CLI/Apple native. Локальные Android .so из предыдущей сборки необходимо пересобрать native/build.sh перед следующим APK; Android в этой задаче не устанавливался.

Внимание: второй BBRsamplingfix сейчас только в local source/artifacts, НЕ в production. Candidate откачен после user connectivity incident. Lab wiDIv8 прошёл60sTCP/10sUDP,320upstream+127workspace testsPASS, WANcandidate109.37DL/66.25ULbidirectional, но long-lived session послеproductionrestartконтрольработал/innerdata0; fresh-smoke этого не поймал. Не считатьrelease-ready без проверки resume+реальногоTUNтрафика послеrestart. Details docs/performance.md. iOSbuild3готов но не установлен, build2 последняяподтверждённаяinstalled.
