# TUN, маршруты, DNS

Крейт `payphone-tun`. Подсеть `10.77.0.0/24` (`PAYPHONE_SUBNET_CIDR`), шлюз `10.77.0.1`.

## MTU

| Константа | Значение | Зачем |
| --- | ---: | --- |
| `PAYPHONE_MTU` | **1100** | старт: 1100 + 40 (frame 16 + data 24) = 1140 ≤ Quinn floor ~1154 (RFC 9000 UDP 1200 минус overhead) |
| `PAYPHONE_MTU_MAX` | 1450 | потолок после path-MTU |
| `PAYPHONE_FRAME_OVERHEAD` | 40 | вычитать из `max_datagram` |

**Не ставить TUN 1280 «потому что IPv6».** Первый толстый браузерный пакет ловил `SendDatagramError::TooLarge`, пока discovery не вырос. После PMTU клиент поднимает интерфейс через `mtu_from_datagram_budget` / `set_interface_mtu`. На macOS utun иногда держит kernel MTU 1500 — его надо принудительно опускать.

## Интерфейсы

- macOS: OS даёт `utunN` (удобно гонять server+client на одной машине).
- Linux: имя `payphone0` у обоих бинарников → конфликт без netns.
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

Linux: `ip_forward=1` + iptables MASQUERADE для `10.77.0.0/24`, FORWARD accept, TCP MSS clamp. Идемпотентно (не плодить правила). В Docker `ip_forward` часто уже включён sysctl с хоста; `/proc` может быть RO — сначала читать, писать только если не `1`. Compose сервера: `sysctls: net.ipv4.ip_forward=1`, `cap_add: NET_ADMIN`, `/dev/net/tun`.

## DNS stub

`payphone-server/src/dns.rs`: UDP на `10.77.0.1:53`, forward на `PAYPHONE_DNS_UPSTREAM` (default `1.1.1.1:53`, fallback `8.8.8.8:53`), timeout 2s. Клиент пинит stub, чтобы при падении туннеля DNS не утёк на ISP. Browser DoH всё равно едет через туннель, минуя stub.

## SIGINT / teardown

1. Снять `/1`, blackhole, host-route, DNS **до** ожидания QUIC.
2. `endpoint.wait_idle()` с таймаутом — иначе первый Ctrl+C зависает, второй никто не слушает, интернет «мёртвый».
3. После стопа должен остаться LAN default, не чёрная дыра.
