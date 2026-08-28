//
// Full-tunnel routing.
//
// Создание TUN-интерфейса само по себе ничего не меняет
// в маршрутизации ОС. Без правок ниже:
//
// - клиент: через TUN идёт трафик ТОЛЬКО к адресам внутри
//   10.77.0.0/24 (например, ping 10.77.0.1); весь остальной
//   трафик (браузер, "какой у меня IP") продолжает идти как
//   раньше, мимо VPN — именно это и наблюдается, если не
//   поменять default route.
//
// - сервер: пакеты долетают до TUN сервера, но дальше в
//   интернет не пересылаются, пока не включён IP forwarding
//   и NAT (MASQUERADE) для подсети туннеля.
//

use std::{io, net::SocketAddr};

/// CIDR подсети PAYPHONE VPN.
pub const PAYPHONE_SUBNET_CIDR: &str = "10.77.0.0/24";

const TUNNEL_GATEWAY: &str = "10.77.0.1";

// =============================================================
// SERVER: forwarding + NAT
// =============================================================

/// Включает IPv4 forwarding и MASQUERADE для `subnet_cidr`.
///
/// Идемпотентно: повторный вызов (например, после рестарта
/// процесса в том же контейнере) не плодит дублирующиеся
/// iptables-правила.
#[cfg(target_os = "linux")]
pub fn enable_server_forwarding(subnet_cidr: &str) -> io::Result<()> {
    //
    // /proc/sys/net/ipv4/ip_forward часто смонтирован read-only
    // внутри контейнера, даже с NET_ADMIN — docker включает его
    // через `--sysctl net.ipv4.ip_forward=1` до старта процесса,
    // а не через запись в этот файл изнутри. Поэтому сначала
    // проверяем текущее значение и пишем, только если оно ещё
    // не "1" — иначе получим ложную ошибку на read-only fs, хотя
    // forwarding уже включён снаружи.
    //
    let already_enabled = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
        .map(|value| value.trim() == "1")
        .unwrap_or(false);

    if !already_enabled {
        std::fs::write("/proc/sys/net/ipv4/ip_forward", b"1").map_err(|error| {
            io::Error::other(format!(
                "failed to enable ip_forward: {error} \
                 (pass `--sysctl net.ipv4.ip_forward=1` to the container instead)"
            ))
        })?;
    }

    linux::ensure_iptables_rule(&[
        "-t",
        "nat",
        "-A",
        "POSTROUTING",
        "-s",
        subnet_cidr,
        "-j",
        "MASQUERADE",
    ])?;

    linux::ensure_iptables_rule(&["-A", "FORWARD", "-s", subnet_cidr, "-j", "ACCEPT"])?;

    linux::ensure_iptables_rule(&["-A", "FORWARD", "-d", subnet_cidr, "-j", "ACCEPT"])?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn enable_server_forwarding(_subnet_cidr: &str) -> io::Result<()> {
    println!(
        "PAYPHONE: forwarding/NAT setup is only implemented for Linux; \
         clients will only reach 10.77.0.0/24, not the wider internet"
    );

    Ok(())
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io;

    //
    // iptables не жалуется, если правило добавить дважды —
    // он просто добавит дубликат. Поэтому сначала проверяем
    // "-C" (check), и только если правила ещё нет, добавляем.
    //
    pub fn ensure_iptables_rule(append_args: &[&str]) -> io::Result<()> {
        let mut check_args = append_args.to_vec();

        let position = check_args
            .iter()
            .position(|arg| *arg == "-A")
            .expect("iptables rule must be expressed as an -A append");

        check_args[position] = "-C";

        let already_present = std::process::Command::new("iptables")
            .args(&check_args)
            .status()
            .map(|status| status.success())
            .unwrap_or(false);

        if already_present {
            return Ok(());
        }

        let status = std::process::Command::new("iptables")
            .args(append_args)
            .status()
            .map_err(|error| io::Error::other(format!("failed to run iptables: {error}")))?;

        if !status.success() {
            return Err(io::Error::other(format!(
                "iptables {append_args:?} exited with {status}"
            )));
        }

        Ok(())
    }
}

// =============================================================
// CLIENT: full-tunnel default route
// =============================================================

/// RAII-guard для full-tunnel маршрутизации на клиенте.
///
/// Пока guard жив — весь IPv4-трафик клиента (кроме пакетов к
/// самому PAYPHONE server, для которых сохраняется исходный
/// путь) идёт через TUN. При Drop (Ctrl+C, ошибка, паника)
/// исходная маршрутизация восстанавливается автоматически —
/// это RAII, а не ручная очистка на каждом пути выхода.
pub struct FullTunnelGuard {
    server_ip: std::net::IpAddr,

    original_gateway: std::net::IpAddr,

    tun_name: String,

    #[cfg(target_os = "macos")]
    ipv6_service: Option<String>,

    #[cfg(target_os = "macos")]
    dns_restore: Option<(String, Vec<String>)>,
}

impl FullTunnelGuard {
    /// Ставит full-tunnel маршруты.
    ///
    /// `server_address` — реальный (не VPN) адрес PAYPHONE
    /// server, к которому уже установлено QUIC-соединение;
    /// `tun_name` — имя TUN-интерфейса клиента.
    #[cfg(target_os = "macos")]
    pub fn install(server_address: SocketAddr, tun_name: &str) -> io::Result<Self> {
        let server_ip = server_address.ip();

        let original_gateway = macos::default_gateway()?;

        //
        // Явный host route к самому серверу через исходный
        // gateway — иначе его же QUIC-пакеты попытаются уйти
        // в TUN и получится петля.
        //
        macos::run_route(&[
            "add",
            "-inet",
            "-host",
            &server_ip.to_string(),
            &original_gateway.to_string(),
        ])?;

        //
        // Next-hop 10.77.0.1 (the utun peer), not `-interface`.
        // On macOS a /1 route bound only to the interface often
        // shows up in netstat but is ignored for real sockets —
        // IPv4 then keeps using the ISP default, which is why
        // 2ip still showed the home address with the tunnel "up".
        //
        macos::run_route(&["add", "-inet", "-net", "0.0.0.0/1", TUNNEL_GATEWAY])?;

        macos::run_route(&["add", "-inet", "-net", "128.0.0.0/1", TUNNEL_GATEWAY])?;

        let ipv6_service = macos::disable_ipv6_on_default_service();

        let dns_restore = macos::pin_dns_through_tunnel();

        Ok(Self {
            server_ip,
            original_gateway,
            tun_name: tun_name.to_string(),
            ipv6_service,
            dns_restore,
        })
    }

    #[cfg(target_os = "linux")]
    pub fn install(server_address: SocketAddr, tun_name: &str) -> io::Result<Self> {
        let server_ip = server_address.ip();

        let original_gateway = linux_route::default_gateway()?;

        linux_route::run_ip(&[
            "route",
            "add",
            &server_ip.to_string(),
            "via",
            &original_gateway.to_string(),
        ])?;

        linux_route::run_ip(&["route", "add", "0.0.0.0/1", "dev", tun_name])?;

        linux_route::run_ip(&["route", "add", "128.0.0.0/1", "dev", tun_name])?;

        Ok(Self {
            server_ip,
            original_gateway,
            tun_name: tun_name.to_string(),
            #[cfg(target_os = "macos")]
            ipv6_service: None,
            #[cfg(target_os = "macos")]
            dns_restore: None,
        })
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    pub fn install(_server_address: SocketAddr, _tun_name: &str) -> io::Result<Self> {
        Err(io::Error::other(
            "full-tunnel routing is only implemented for macOS and Linux",
        ))
    }
}

impl Drop for FullTunnelGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        {
            if let Some((service, servers)) = self.dns_restore.take() {
                macos::restore_dns(&service, &servers);
            }

            if let Some(service) = self.ipv6_service.take() {
                let _ = macos::run_networksetup(&["-setv6automatic", &service]);
            }

            let _ = self.tun_name.as_str();

            let _ = macos::run_route(&["delete", "-inet", "-net", "128.0.0.0/1", TUNNEL_GATEWAY]);

            let _ = macos::run_route(&["delete", "-inet", "-net", "0.0.0.0/1", TUNNEL_GATEWAY]);

            let _ = macos::run_route(&[
                "delete",
                "-inet",
                "-host",
                &self.server_ip.to_string(),
                &self.original_gateway.to_string(),
            ]);
        }

        #[cfg(target_os = "linux")]
        {
            let _ = linux_route::run_ip(&["route", "del", "128.0.0.0/1", "dev", &self.tun_name]);

            let _ = linux_route::run_ip(&["route", "del", "0.0.0.0/1", "dev", &self.tun_name]);

            let _ = linux_route::run_ip(&[
                "route",
                "del",
                &self.server_ip.to_string(),
                "via",
                &self.original_gateway.to_string(),
            ]);
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::{io, net::IpAddr, process::Command};

    pub fn default_gateway() -> io::Result<IpAddr> {
        let output = Command::new("route")
            .args(["-n", "get", "default"])
            .output()?;

        if !output.status.success() {
            return Err(io::Error::other("`route -n get default` failed"));
        }

        let text = String::from_utf8_lossy(&output.stdout);

        for line in text.lines() {
            if let Some(value) = line.trim().strip_prefix("gateway:") {
                let value = value.trim();

                return value.parse::<IpAddr>().map_err(|_| {
                    io::Error::other(format!("cannot parse default gateway: {value}"))
                });
            }
        }

        Err(io::Error::other(
            "no default gateway found in `route -n get default` output",
        ))
    }

    pub fn run_route(args: &[&str]) -> io::Result<()> {
        let output = Command::new("route").args(args).output()?;

        if !output.status.success() {
            return Err(io::Error::other(format!(
                "route {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(())
    }

    pub fn run_networksetup(args: &[&str]) -> io::Result<String> {
        let output = Command::new("networksetup").args(args).output()?;

        if !output.status.success() {
            return Err(io::Error::other(format!(
                "networksetup {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn default_interface() -> io::Result<String> {
        let output = Command::new("route")
            .args(["-n", "get", "default"])
            .output()?;

        if !output.status.success() {
            return Err(io::Error::other("`route -n get default` failed"));
        }

        let text = String::from_utf8_lossy(&output.stdout);

        for line in text.lines() {
            if let Some(value) = line.trim().strip_prefix("interface:") {
                return Ok(value.trim().to_string());
            }
        }

        Err(io::Error::other(
            "no interface found in `route -n get default` output",
        ))
    }

    fn service_for_device(device: &str) -> io::Result<String> {
        let text = run_networksetup(&["-listnetworkserviceorder"])?;

        let mut last_service: Option<String> = None;

        for line in text.lines() {
            let line = line.trim();

            if let Some(name) = line.strip_prefix("(").and_then(|rest| {
                rest.split_once(") ")
                    .filter(|(index, _)| index.chars().all(|c| c.is_ascii_digit()))
                    .map(|(_, name)| name.to_string())
            }) {
                last_service = Some(name);

                continue;
            }

            let marker = format!("Device: {device}");

            if line.contains(&marker) {
                if let Some(service) = last_service {
                    return Ok(service);
                }
            }
        }

        Err(io::Error::other(format!(
            "no networksetup service for device {device}"
        )))
    }

    /// Dual-stack ISPs (Rostelecom etc.) keep IPv6 on the physical
    /// NIC. Browsers prefer it, so 2ip shows the home address even
    /// while IPv4 is inside the tunnel. Turn IPv6 off on the default
    /// service for the life of the guard.
    pub fn disable_ipv6_on_default_service() -> Option<String> {
        let device = default_interface().ok()?;

        let service = service_for_device(&device).ok()?;

        run_networksetup(&["-setv6off", &service]).ok()?;

        Some(service)
    }

    /// Point macOS DNS at resolvers that only exist as public IPv4,
    /// so lookups take the tunnel instead of the ISP CPE at 192.168.x.x.
    pub fn pin_dns_through_tunnel() -> Option<(String, Vec<String>)> {
        let device = default_interface().ok()?;

        let service = service_for_device(&device).ok()?;

        let current = run_networksetup(&["-getdnsservers", &service]).ok()?;

        let original: Vec<String> = if current.contains("aren't any DNS Servers")
            || current.contains("There aren't any DNS Servers")
        {
            Vec::new()
        } else {
            current
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        };

        run_networksetup(&["-setdnsservers", &service, "1.1.1.1", "8.8.8.8"]).ok()?;

        Some((service, original))
    }

    pub fn restore_dns(service: &str, servers: &[String]) {
        if servers.is_empty() {
            let _ = run_networksetup(&["-setdnsservers", service, "Empty"]);
        } else {
            let mut args = vec!["-setdnsservers", service];

            for server in servers {
                args.push(server.as_str());
            }

            let _ = run_networksetup(&args);
        }
    }
}

#[cfg(target_os = "linux")]
mod linux_route {
    use std::{io, net::IpAddr, process::Command};

    pub fn default_gateway() -> io::Result<IpAddr> {
        let output = Command::new("ip")
            .args(["route", "show", "default"])
            .output()?;

        if !output.status.success() {
            return Err(io::Error::other("`ip route show default` failed"));
        }

        let text = String::from_utf8_lossy(&output.stdout);

        let mut fields = text.split_whitespace();

        while let Some(field) = fields.next() {
            if field == "via" {
                if let Some(value) = fields.next() {
                    return value.parse::<IpAddr>().map_err(|_| {
                        io::Error::other(format!("cannot parse default gateway: {value}"))
                    });
                }
            }
        }

        Err(io::Error::other(
            "no default gateway found in `ip route show default` output",
        ))
    }

    pub fn run_ip(args: &[&str]) -> io::Result<()> {
        let output = Command::new("ip").args(args).output()?;

        if !output.status.success() {
            return Err(io::Error::other(format!(
                "ip {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(())
    }
}
