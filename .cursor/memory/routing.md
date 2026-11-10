# TUN, маршруты, DNS

Крейт `payphone-tun`. Подсеть `10.77.0.0/16` (`PAYPHONE_SUBNET_CIDR`), шлюз `10.77.0.1`.

## MTU

| Константа | Значение | Зачем |
| --- | ---: | --- |
| `PAYPHONE_MTU` | **1100** | старт: 1100 + 40 (frame 16 + data 24) = 1140 ≤ Quinn floor ~1154 (RFC 9000 UDP 1200 минус overhead) |
| `PAYPHONE_MTU_MAX` | 1450 | потолок server TUN / TLS; QUIC использует фактический меньший бюджет |
| `PAYPHONE_FRAME_OVERHEAD` | 40 | вычитать из `max_datagram` |

**Не ставить TUN 1280 «потому что IPv6».** Первый толстый браузерный пакет ловил `SendDatagramError::TooLarge`, пока discovery не вырос. Клиент выставляет интерфейс по фактическому бюджету через `mtu_from_datagram_budget` / `set_interface_mtu` (сейчас QUIC 1200 без PMTUD, измеренный TUN budget 1122). Linux использует `tun-rs::set_mtu` (ioctl), а не внешний `ifconfig`, которого может не быть в контейнере. На macOS utun иногда держит kernel MTU 1500 — его надо принудительно опускать.

## Интерфейсы

- macOS: OS даёт `utunN` (удобно гонять server+client на одной машине).
- Linux: имя `payphone0` у обоих бинарников → конфликт без netns. TX queue 8192 packets через DeviceBuilder::tx_queue_len: старые 500 переполнялись при 300 Mbps (~14ms запаса на scheduler), 2048 также не выдержали одного >100ms всплеска. 8192 даёт ~220ms для ~1KiB packets; проверять loaded RTT, это не гарантия отсутствия потерь.
- Windows: `wintun.dll` рядом с клиентом, процесс Administrator.

`SharedTun = Arc<AsyncDevice>`: TUN→wire и wire→TUN параллельно.

## Full-tunnel (клиент)

Не трогать default route. Два более специфичных:

- `0.0.0.0/1` и `128.0.0.0/1` через `10.77.0.1`
- Host `/32` на IP сервера через LAN-шлюз (иначе `/1` заглатывает VPS и QUIC уходит в свой TUN — петля)
- IPv6: blackhole `::/1` + `8000::/1` (иначе браузер уезжает на AAAA провайдера)
- DNS: пин на `10.77.0.1`. Windows — catch-all NRPT, чтобы LAN-резолвер не отвечал
- macOS: **не вызывать `networksetup`** (ломает таблицу маршрутов). IPv6 — `route -blackhole`, DNS — `scutil`. Нужен **unscoped** `/32`, не только `-ifscope`. UDP: `IP_BOUND_IF` на Wi-Fi. Watchdog маршрутов — отдельный `interval` ~400ms, **не** таймер внутри `select` на каждый TUN-пакет

Kill-switch (`--kill-switch` / `PAYPHONE_KILL_SWITCH`, default **off**): пока клиент жив, IPv4 тоже в blackhole если туннель упал. On-link LAN (`192.168.x` и т.п.) не режется. Ctrl+C обязан вернуть LAN.

## Full-tunnel (сервер)

Linux: `ip_forward=1` + iptables MASQUERADE для `10.77.0.0/16`, FORWARD accept, TCP MSS clamp. Идемпотентно (не плодить правила). В Docker `ip_forward` часто уже включён sysctl с хоста; `/proc` может быть RO — сначала читать, писать только если не `1`. Compose сервера: `sysctls: net.ipv4.ip_forward=1`, `cap_add: NET_ADMIN`, `/dev/net/tun`.

## DNS stub

`payphone-server/src/dns.rs`: UDP на `10.77.0.1:53`, forward на `PAYPHONE_DNS_UPSTREAM` (default `1.1.1.1:53`, fallback `8.8.8.8:53`), timeout 2s. Клиент пинит stub, чтобы при падении туннеля DNS не утёк на ISP. Browser DoH всё равно едет через туннель, минуя stub.

## SIGINT / teardown

1. Снять `/1`, blackhole, host-route, DNS **до** ожидания QUIC.
2. `endpoint.wait_idle()` с таймаутом — иначе первый Ctrl+C зависает, второй никто не слушает, интернет «мёртвый».
3. После стопа должен остаться LAN default, не чёрная дыра.

## Адресный пул и MTU на выходе

Пул: `10.77.0.2`–`10.77.255.254` (65 533 сессии), `.0.0`/`.0.1`/`.255.255` зарезервированы. Rust/Android/Apple используют prefix 16. При обновлении сервера со старого `/24` обновить клиенты: старый Rust-клиент может не установить gateway для адресов вне первой `/24`. Формат AllGoodDude/StillGoodDude и store v1 не изменён.

Серверный TUN остаётся 1450; `forward.rs` сначала пытается enqueue, после отказа сверяет IP с `ClientLink::ip_mtu` (max_datagram_size минус 40). Крупные DF=0 фрагментируются по IPv4, DF=1 вызывает ICMP type 3/code 4 в TUN к отправителю (rate limited). ICMP ошибки/непервые фрагменты не вызывают новые ICMP ошибки. На Rust-клиенте тот же `ipv4::fit_packet` закрывает промежуток до обновления MTU интерфейса. Не менять старт 1100.

Watchdog маршрутов выполняет OS-команды через `spawn_blocking`, не в TUN select-loop; максимум одна задача одновременно. `FullTunnelGuard::teardown(&self)` идемпотентен и синхронизирован mutex с ensure_tunnel_routes: ожидает текущее обслуживание, отключает будущие вызовы, затем снимает маршруты. Клиентский TunnelRoutes владеет Arc и вызывает teardown в Drop даже при `?`; retained Arc watchdog не должен задерживать очистку. Не заменять owner на голый Arc: поздний restore после teardown и ожидание последнего Arc нарушают безопасный выход.

Linux route watchdog сначала читает /proc/net/route и /proc/net/ipv6_route: здоровые /1 и server /32 не переписывать каждые400ms — это вызывало секундные провалы throughput. Проверять интерфейс, gateway, flags и лучшую metric (равные конкурирующие неправильные routes считаются нарушением); IPv6 требует обе безусловные reject /1. При несовпадении/ошибке чтения восстанавливать как раньше. DNS pin продолжает обслуживаться. Lab до нагрузки удаляет по очереди все пять маршрутов и проверяет восстановление, затем проверяет SIGINT teardown. Временный env для отключения watchdog удалён.
