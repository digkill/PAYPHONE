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

    linux::ensure_iptables_rule(&[
        "-t",
        "mangle",
        "-A",
        "FORWARD",
        "-p",
        "tcp",
        "--tcp-flags",
        "SYN,RST",
        "SYN",
        "-j",
        "TCPMSS",
        "--clamp-mss-to-pmtu",
    ])?;

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

    /// When set, Drop keeps the kill-switch block (no ISP default).
    kill_switch: bool,

    #[cfg(target_os = "macos")]
    physical_iface: String,
}

impl FullTunnelGuard {
    /// Ставит full-tunnel маршруты.
    ///
    /// `server_address` — реальный (не VPN) адрес PAYPHONE
    /// server, к которому уже установлено QUIC-соединение;
    /// `tun_name` — имя TUN-интерфейса клиента.
    #[cfg(target_os = "macos")]
    pub fn install(
        server_address: SocketAddr,
        tun_name: &str,
        kill_switch: bool,
    ) -> io::Result<Self> {
        let server_ip = server_address.ip();

        let original_gateway = macos::default_gateway()?;

        let physical_iface = macos::default_interface()?;

        //
        // Do not call `networksetup`. It rebuilds the routing table
        // and wipes both the /32 server bypass and the /1 tunnel
        // routes — QUIC then enters utun and the session dies.
        // IPv6 is blackholed with `route`; DNS is pinned via scutil.
        //
        macos::install_tunnel_routes(server_ip, original_gateway, &physical_iface)?;

        macos::add_ipv6_blackholes();

        macos::pin_dns_scutil();

        Ok(Self {
            server_ip,
            original_gateway,
            tun_name: tun_name.to_string(),
            kill_switch,
            physical_iface,
        })
    }

    /// macOS (DHCP, sleep, configd) can delete our routes while
    /// the tunnel is up. Re-assert the unscoped /32 bypass and
    /// both /1 defaults. Must be called from a real interval —
    /// not a sleep that is recreated on every VPN-loop iteration.
    pub fn ensure_tunnel_routes(&self) {
        #[cfg(target_os = "macos")]
        {
            macos::restore_tunnel_routes(
                self.server_ip,
                self.original_gateway,
                &self.physical_iface,
            );
        }

        #[cfg(target_os = "windows")]
        {
            windows_route::restore_tunnel_routes(
                self.server_ip,
                self.original_gateway,
                &self.tun_name,
            );
        }

        #[cfg(target_os = "linux")]
        {
            linux_route::restore_tunnel_routes(
                self.server_ip,
                self.original_gateway,
                &self.tun_name,
            );
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            let _ = self;
        }
    }

    #[cfg(target_os = "linux")]
    pub fn install(
        server_address: SocketAddr,
        tun_name: &str,
        kill_switch: bool,
    ) -> io::Result<Self> {
        let server_ip = server_address.ip();

        let original_gateway = linux_route::default_gateway()?;

        linux_route::run_ip(&[
            "route",
            "replace",
            &server_ip.to_string(),
            "via",
            &original_gateway.to_string(),
        ])?;

        linux_route::run_ip(&["route", "replace", "0.0.0.0/1", "dev", tun_name])?;

        linux_route::run_ip(&["route", "replace", "128.0.0.0/1", "dev", tun_name])?;

        linux_route::add_ipv6_blackholes();

        linux_route::pin_dns(tun_name);

        Ok(Self {
            server_ip,
            original_gateway,
            tun_name: tun_name.to_string(),
            kill_switch,
        })
    }

    #[cfg(target_os = "windows")]
    pub fn install(
        server_address: SocketAddr,
        tun_name: &str,
        kill_switch: bool,
    ) -> io::Result<Self> {
        let server_ip = server_address.ip();
        let original_gateway = windows_route::default_gateway()?;
        windows_route::add_host_bypass(server_ip, original_gateway)?;
        windows_route::add_split_default(windows_route::interface_index(tun_name))?;
        windows_route::add_ipv6_blackholes();
        windows_route::pin_dns(tun_name);

        Ok(Self {
            server_ip,
            original_gateway,
            tun_name: tun_name.to_string(),
            kill_switch,
        })
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    pub fn install(
        _server_address: SocketAddr,
        _tun_name: &str,
        _kill_switch: bool,
    ) -> io::Result<Self> {
        Err(io::Error::other(
            "full-tunnel routing is only implemented for macOS, Linux, and Windows",
        ))
    }
}

impl Drop for FullTunnelGuard {
    fn drop(&mut self) {
        if self.kill_switch {
            #[cfg(target_os = "macos")]
            {
                macos::rearm_kill_switch(
                    self.server_ip,
                    self.original_gateway,
                    &self.physical_iface,
                );
            }

            #[cfg(target_os = "linux")]
            {
                linux_route::rearm_kill_switch(self.server_ip, self.original_gateway);
            }

            #[cfg(target_os = "windows")]
            {
                windows_route::rearm_kill_switch(self.server_ip, self.original_gateway);
            }

            return;
        }

        #[cfg(target_os = "macos")]
        {
            let _ = self.tun_name.as_str();

            macos::teardown_tunnel(self.server_ip, self.original_gateway, &self.physical_iface);
        }

        #[cfg(target_os = "linux")]
        {
            linux_route::clear_dns(&self.tun_name);

            linux_route::remove_ipv6_blackholes();

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

        #[cfg(target_os = "windows")]
        {
            windows_route::teardown(self.server_ip, self.original_gateway, &self.tun_name);
        }
    }
}

/// Blocks Internet except the PAYPHONE server while the client process
/// is running. Full-tunnel `/1` via TUN overlays this; if the tunnel
/// drops, the blackholes remain until this guard is dropped (Ctrl+C).
pub struct KillSwitchGuard {
    server_ip: std::net::IpAddr,
    original_gateway: std::net::IpAddr,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    physical_iface: String,
}

impl KillSwitchGuard {
    pub fn install(server_address: SocketAddr) -> io::Result<Self> {
        #[cfg(target_os = "macos")]
        {
            let server_ip = server_address.ip();
            let original_gateway = macos::default_gateway()?;
            let physical_iface = macos::default_interface()?;
            macos::add_host_bypass(server_ip, original_gateway, &physical_iface)?;
            macos::add_ipv4_blackholes();
            macos::add_ipv6_blackholes();
            macos::pin_dns_scutil();
            Ok(Self {
                server_ip,
                original_gateway,
                physical_iface,
            })
        }

        #[cfg(target_os = "linux")]
        {
            let server_ip = server_address.ip();
            let original_gateway = linux_route::default_gateway()?;
            let physical_iface = linux_route::default_interface()?;
            linux_route::run_ip(&[
                "route",
                "replace",
                &server_ip.to_string(),
                "via",
                &original_gateway.to_string(),
            ])?;
            linux_route::add_ipv4_blackholes();
            linux_route::add_ipv6_blackholes();
            linux_route::pin_dns(&physical_iface);
            Ok(Self {
                server_ip,
                original_gateway,
                physical_iface,
            })
        }

        #[cfg(target_os = "windows")]
        {
            let server_ip = server_address.ip();
            let original_gateway = windows_route::default_gateway()?;
            windows_route::add_host_bypass(server_ip, original_gateway)?;
            windows_route::add_ipv4_blackholes()?;
            windows_route::add_ipv6_blackholes();
            windows_route::pin_nrpt();
            let _ = server_address;
            Ok(Self {
                server_ip,
                original_gateway,
            })
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            let _ = server_address;
            Err(io::Error::other(
                "kill switch is only implemented for macOS, Linux, and Windows",
            ))
        }
    }

    pub fn ensure(&self) {
        #[cfg(target_os = "macos")]
        {
            macos::rearm_kill_switch(self.server_ip, self.original_gateway, &self.physical_iface);
        }

        #[cfg(target_os = "linux")]
        {
            linux_route::rearm_kill_switch(self.server_ip, self.original_gateway);
            linux_route::pin_dns(&self.physical_iface);
        }

        #[cfg(target_os = "windows")]
        {
            windows_route::rearm_kill_switch(self.server_ip, self.original_gateway);
            windows_route::pin_nrpt();
        }
    }
}

impl Drop for KillSwitchGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        {
            macos::teardown_tunnel(self.server_ip, self.original_gateway, &self.physical_iface);
        }

        #[cfg(target_os = "linux")]
        {
            linux_route::clear_dns(&self.physical_iface);
            linux_route::remove_ipv6_blackholes();
            linux_route::remove_ipv4_blackholes();
            let _ = linux_route::run_ip(&[
                "route",
                "del",
                &self.server_ip.to_string(),
                "via",
                &self.original_gateway.to_string(),
            ]);
        }

        #[cfg(target_os = "windows")]
        {
            windows_route::disarm_kill_switch(self.server_ip, self.original_gateway);
            windows_route::clear_nrpt();
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
            let stderr = String::from_utf8_lossy(&output.stderr);

            if stderr.contains("File exists") || stderr.contains("not in table") {
                return Ok(());
            }

            return Err(io::Error::other(format!(
                "route {} failed: {}",
                args.join(" "),
                stderr
            )));
        }

        Ok(())
    }

    pub fn default_interface() -> io::Result<String> {
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

    pub fn install_tunnel_routes(
        server_ip: IpAddr,
        gateway: IpAddr,
        iface: &str,
    ) -> io::Result<()> {
        add_host_bypass(server_ip, gateway, iface)?;

        // Kill-switch blackholes use the same prefixes. Drop them so
        // the TUN /1 can be installed; FullTunnel Drop puts them back.
        let _ = run_route(&["delete", "-inet", "-blackhole", "0.0.0.0/1"]);
        let _ = run_route(&["delete", "-inet", "-blackhole", "128.0.0.0/1"]);
        let _ = run_route(&["delete", "-inet", "-net", "0.0.0.0/1"]);
        let _ = run_route(&["delete", "-inet", "-net", "128.0.0.0/1"]);

        run_route(&["add", "-inet", "-net", "0.0.0.0/1", super::TUNNEL_GATEWAY])?;

        run_route(&["add", "-inet", "-net", "128.0.0.0/1", super::TUNNEL_GATEWAY])?;

        add_host_bypass(server_ip, gateway, iface)
    }

    pub fn restore_tunnel_routes(server_ip: IpAddr, gateway: IpAddr, iface: &str) {
        if !host_route_ok(server_ip, gateway) {
            let _ = add_host_bypass(server_ip, gateway, iface);
        }

        if !split_default_ok() {
            let _ = add_host_bypass(server_ip, gateway, iface);

            let _ = run_route(&["add", "-inet", "-net", "0.0.0.0/1", super::TUNNEL_GATEWAY]);

            let _ = run_route(&["add", "-inet", "-net", "128.0.0.0/1", super::TUNNEL_GATEWAY]);

            let _ = add_host_bypass(server_ip, gateway, iface);
        }

        if !ipv6_blackholes_ok() {
            add_ipv6_blackholes();
        }

        refresh_dns_scutil();
    }

    /// Unscoped /32 via the LAN gateway. `-ifscope` alone is not
    /// enough: Quinn and most sockets do an unscoped lookup, which
    /// still matches 128.0.0.0/1 → utun and kills QUIC.
    pub fn add_host_bypass(server_ip: IpAddr, gateway: IpAddr, iface: &str) -> io::Result<()> {
        let dest = server_ip.to_string();

        let gw = gateway.to_string();

        let _ = run_route(&["delete", "-ifscope", iface, "-inet", "-host", &dest]);

        let _ = run_route(&["delete", "-inet", "-host", &dest]);

        run_route(&["add", "-inet", "-host", &dest, &gw])?;

        let _ = run_route(&["add", "-ifscope", iface, "-inet", "-host", &dest, &gw]);

        Ok(())
    }

    fn route_get_inet(dest: &str) -> Option<(Option<String>, Option<String>)> {
        let output = Command::new("route")
            .args(["-n", "get", "-inet", dest])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let text = String::from_utf8_lossy(&output.stdout);

        let mut gateway = None;

        let mut iface = None;

        for line in text.lines() {
            let line = line.trim();

            if let Some(value) = line.strip_prefix("gateway:") {
                gateway = Some(value.trim().to_string());
            }

            if let Some(value) = line.strip_prefix("interface:") {
                iface = Some(value.trim().to_string());
            }
        }

        Some((gateway, iface))
    }

    pub fn host_route_ok(server_ip: IpAddr, expected_gateway: IpAddr) -> bool {
        let Some((gateway, iface)) = route_get_inet(&server_ip.to_string()) else {
            return false;
        };

        let Some(gateway) = gateway else {
            return false;
        };

        if gateway.parse::<IpAddr>().ok() != Some(expected_gateway) {
            return false;
        }

        if let Some(iface) = iface {
            if iface.starts_with("utun") || iface == "lo0" {
                return false;
            }
        }

        true
    }

    fn split_default_ok() -> bool {
        let Some((gateway, iface)) = route_get_inet("8.8.8.8") else {
            return false;
        };

        if gateway.as_deref() == Some(super::TUNNEL_GATEWAY) {
            return true;
        }

        iface
            .as_deref()
            .is_some_and(|name| name.starts_with("utun"))
    }

    pub fn add_ipv6_blackholes() {
        let _ = run_route(&["add", "-inet6", "-blackhole", "::/1"]);

        let _ = run_route(&["add", "-inet6", "-blackhole", "8000::/1"]);
    }

    pub fn add_ipv4_blackholes() {
        let _ = run_route(&[
            "delete",
            "-inet",
            "-net",
            "0.0.0.0/1",
            super::TUNNEL_GATEWAY,
        ]);
        let _ = run_route(&[
            "delete",
            "-inet",
            "-net",
            "128.0.0.0/1",
            super::TUNNEL_GATEWAY,
        ]);
        let _ = run_route(&["delete", "-inet", "-net", "0.0.0.0/1"]);
        let _ = run_route(&["delete", "-inet", "-net", "128.0.0.0/1"]);
        let _ = run_route(&["add", "-inet", "-blackhole", "0.0.0.0/1"]);
        let _ = run_route(&["add", "-inet", "-blackhole", "128.0.0.0/1"]);
    }

    pub fn rearm_kill_switch(server_ip: IpAddr, gateway: IpAddr, iface: &str) {
        let _ = add_host_bypass(server_ip, gateway, iface);
        add_ipv4_blackholes();
        add_ipv6_blackholes();
        pin_dns_scutil();
    }

    pub fn remove_ipv6_blackholes() {
        let _ = run_route(&["delete", "-inet6", "::/1"]);

        let _ = run_route(&["delete", "-inet6", "8000::/1"]);
    }

    fn ipv6_blackholes_ok() -> bool {
        let output = Command::new("route")
            .args(["-n", "get", "-inet6", "2001:4860:4860::8888"])
            .output();

        let Ok(output) = output else {
            return true;
        };

        if !output.status.success() {
            return true;
        }

        let text = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();

        text.contains("blackhole") || text.contains("interface: lo0")
    }

    fn scutil(script: &str) {
        use std::io::Write;
        use std::process::Stdio;

        let Ok(mut child) = Command::new("scutil")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            return;
        };

        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(script.as_bytes());
        }

        let _ = child.wait();
    }

    pub fn pin_dns_scutil() {
        set_dns_scutil();

        let _ = Command::new("killall")
            .args(["-HUP", "mDNSResponder"])
            .status();
    }

    pub fn refresh_dns_scutil() {
        set_dns_scutil();
    }

    fn set_dns_scutil() {
        //
        // VPN-only resolver. 1.1.1.1 used to leak to the ISP if the
        // /1 routes vanished; 10.77.0.1 is unreachable off-tunnel.
        //
        let dns = crate::SERVER_TUN_IPV4.to_string();

        scutil(&format!(
            "d.init\n\
             d.add ServerAddresses * {dns}\n\
             d.add SupplementalMatchDomains * \"\"\n\
             set State:/Network/Service/PAYPHONE/DNS\n"
        ));
    }

    pub fn clear_dns_scutil() {
        scutil(
            "remove State:/Network/Service/PAYPHONE/DNS\n\
             remove Setup:/Network/Service/PAYPHONE/DNS\n",
        );

        let _ = Command::new("killall")
            .args(["-HUP", "mDNSResponder"])
            .status();
    }

    fn lan_default_ok() -> bool {
        let output = Command::new("route")
            .args(["-n", "get", "default"])
            .output();

        let Ok(output) = output else {
            return false;
        };

        if !output.status.success() {
            return false;
        }

        let text = String::from_utf8_lossy(&output.stdout);

        text.contains("gateway:") && !text.contains("interface: utun")
    }

    fn ensure_lan_default(gateway: IpAddr, iface: &str) {
        if lan_default_ok() {
            return;
        }

        let gw = gateway.to_string();

        let _ = run_route(&["delete", "default"]);

        let _ = run_route(&["add", "default", &gw]);

        let _ = run_route(&["add", "-ifscope", iface, "default", &gw]);
    }

    pub fn teardown_tunnel(server_ip: IpAddr, gateway: IpAddr, iface: &str) {
        let dest = server_ip.to_string();

        let _ = run_route(&[
            "delete",
            "-inet",
            "-net",
            "128.0.0.0/1",
            super::TUNNEL_GATEWAY,
        ]);

        let _ = run_route(&[
            "delete",
            "-inet",
            "-net",
            "0.0.0.0/1",
            super::TUNNEL_GATEWAY,
        ]);

        let _ = run_route(&["delete", "-inet", "-net", "128.0.0.0/1"]);

        let _ = run_route(&["delete", "-inet", "-net", "0.0.0.0/1"]);

        let _ = run_route(&["delete", "-ifscope", iface, "-inet", "-host", &dest]);

        let _ = run_route(&["delete", "-inet", "-host", &dest]);

        remove_ipv6_blackholes();

        let _ = run_route(&["delete", "-inet6", "-blackhole", "::/1"]);

        let _ = run_route(&["delete", "-inet6", "-blackhole", "8000::/1"]);

        clear_dns_scutil();

        ensure_lan_default(gateway, iface);
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

    pub fn default_interface() -> io::Result<String> {
        let output = Command::new("ip")
            .args(["route", "show", "default"])
            .output()?;

        if !output.status.success() {
            return Err(io::Error::other("`ip route show default` failed"));
        }

        super::parse_linux_default_iface(&String::from_utf8_lossy(&output.stdout))
            .ok_or_else(|| io::Error::other("no default interface in `ip route show default`"))
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

    pub fn pin_dns(tun_name: &str) {
        let dns = crate::SERVER_TUN_IPV4.to_string();

        let _ = Command::new("resolvectl")
            .args(["dns", tun_name, &dns])
            .status();

        let _ = Command::new("resolvectl")
            .args(["domain", tun_name, "~."])
            .status();

        let _ = Command::new("resolvectl")
            .args(["default-route", tun_name, "yes"])
            .status();
    }

    pub fn add_ipv6_blackholes() {
        let _ = run_ip(&["-6", "route", "replace", "blackhole", "::/1"]);
        let _ = run_ip(&["-6", "route", "replace", "blackhole", "8000::/1"]);
    }

    pub fn add_ipv4_blackholes() {
        let _ = run_ip(&["route", "replace", "blackhole", "0.0.0.0/1"]);
        let _ = run_ip(&["route", "replace", "blackhole", "128.0.0.0/1"]);
    }

    pub fn remove_ipv4_blackholes() {
        let _ = run_ip(&["route", "del", "blackhole", "0.0.0.0/1"]);
        let _ = run_ip(&["route", "del", "blackhole", "128.0.0.0/1"]);
    }

    pub fn rearm_kill_switch(server_ip: IpAddr, gateway: IpAddr) {
        let _ = run_ip(&[
            "route",
            "replace",
            &server_ip.to_string(),
            "via",
            &gateway.to_string(),
        ]);
        add_ipv4_blackholes();
        add_ipv6_blackholes();
    }

    pub fn remove_ipv6_blackholes() {
        let _ = run_ip(&["-6", "route", "del", "blackhole", "::/1"]);
        let _ = run_ip(&["-6", "route", "del", "blackhole", "8000::/1"]);
    }

    pub fn restore_tunnel_routes(server_ip: IpAddr, gateway: IpAddr, tun_name: &str) {
        let _ = run_ip(&[
            "route",
            "replace",
            &server_ip.to_string(),
            "via",
            &gateway.to_string(),
        ]);
        let _ = run_ip(&["route", "replace", "0.0.0.0/1", "dev", tun_name]);
        let _ = run_ip(&["route", "replace", "128.0.0.0/1", "dev", tun_name]);
        add_ipv6_blackholes();
        pin_dns(tun_name);
    }

    pub fn clear_dns(tun_name: &str) {
        let _ = Command::new("resolvectl")
            .args(["revert", tun_name])
            .status();
    }
}

#[cfg(target_os = "windows")]
mod windows_route {
    use std::{io, net::IpAddr, process::Command};

    pub fn default_gateway() -> io::Result<IpAddr> {
        let output = Command::new("route").args(["print", "-4"]).output()?;

        if !output.status.success() {
            return Err(io::Error::other("`route print -4` failed"));
        }

        super::parse_windows_route_print_gateway(&String::from_utf8_lossy(&output.stdout))
            .ok_or_else(|| io::Error::other("no IPv4 default gateway in `route print -4`"))
    }

    pub fn interface_index(tun_name: &str) -> Option<u32> {
        let output = Command::new("netsh")
            .args(["interface", "ipv4", "show", "interfaces"])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        super::parse_netsh_interface_index(&String::from_utf8_lossy(&output.stdout), tun_name)
    }

    pub fn add_host_bypass(server_ip: IpAddr, gateway: IpAddr) -> io::Result<()> {
        let ip = server_ip.to_string();
        let gw = gateway.to_string();
        let _ = run_route(&["delete", &ip, "mask", "255.255.255.255", &gw]);
        run_route(&["add", &ip, "mask", "255.255.255.255", &gw, "metric", "1"])
    }

    pub fn add_split_default(if_index: Option<u32>) -> io::Result<()> {
        add_split("0.0.0.0", if_index)?;
        add_split("128.0.0.0", if_index)
    }

    fn add_split(network: &str, if_index: Option<u32>) -> io::Result<()> {
        let gw = super::TUNNEL_GATEWAY;
        let if_text = if_index.map(|idx| idx.to_string());
        let mut delete = vec!["delete", network, "mask", "128.0.0.0", gw];
        let mut add = vec!["add", network, "mask", "128.0.0.0", gw, "metric", "1"];
        if let Some(idx) = if_text.as_deref() {
            delete.extend_from_slice(&["IF", idx]);
            add.extend_from_slice(&["IF", idx]);
        }
        let _ = run_route(&delete);
        run_route(&add)
    }

    pub fn restore_tunnel_routes(server_ip: IpAddr, gateway: IpAddr, tun_name: &str) {
        let _ = add_host_bypass(server_ip, gateway);
        let _ = add_split_default(interface_index(tun_name));
        add_ipv6_blackholes();
        pin_dns(tun_name);
    }

    pub fn add_ipv4_blackholes() -> io::Result<()> {
        let _ = run_route(&["delete", "0.0.0.0", "mask", "128.0.0.0"]);
        let _ = run_route(&["delete", "128.0.0.0", "mask", "128.0.0.0"]);
        run_route(&[
            "add",
            "0.0.0.0",
            "mask",
            "128.0.0.0",
            "127.0.0.1",
            "metric",
            "400",
        ])?;
        run_route(&[
            "add",
            "128.0.0.0",
            "mask",
            "128.0.0.0",
            "127.0.0.1",
            "metric",
            "400",
        ])
    }

    pub fn rearm_kill_switch(server_ip: IpAddr, gateway: IpAddr) {
        let _ = add_host_bypass(server_ip, gateway);
        let _ = add_ipv4_blackholes();
        add_ipv6_blackholes();
    }

    pub fn disarm_kill_switch(server_ip: IpAddr, gateway: IpAddr) {
        let _ = run_route(&["delete", "0.0.0.0", "mask", "128.0.0.0", "127.0.0.1"]);
        let _ = run_route(&["delete", "128.0.0.0", "mask", "128.0.0.0", "127.0.0.1"]);
        remove_ipv6_blackholes();
        let _ = run_route(&[
            "delete",
            &server_ip.to_string(),
            "mask",
            "255.255.255.255",
            &gateway.to_string(),
        ]);
    }

    pub fn add_ipv6_blackholes() {
        // Loopback (idx 1) swallows IPv6 so browsers fall back to IPv4 in the tunnel.
        let _ = run_netsh(&[
            "interface",
            "ipv6",
            "add",
            "route",
            "::/1",
            "interface=1",
            "metric=1",
            "store=active",
        ]);
        let _ = run_netsh(&[
            "interface",
            "ipv6",
            "add",
            "route",
            "8000::/1",
            "interface=1",
            "metric=1",
            "store=active",
        ]);
    }

    pub fn remove_ipv6_blackholes() {
        let _ = run_netsh(&[
            "interface",
            "ipv6",
            "delete",
            "route",
            "::/1",
            "interface=1",
            "store=active",
        ]);
        let _ = run_netsh(&[
            "interface",
            "ipv6",
            "delete",
            "route",
            "8000::/1",
            "interface=1",
            "store=active",
        ]);
    }

    pub fn pin_dns(tun_name: &str) {
        let dns = crate::SERVER_TUN_IPV4.to_string();
        let _ = run_netsh(&[
            "interface",
            "ipv4",
            "set",
            "dnsservers",
            &format!("name={tun_name}"),
            "static",
            &dns,
            "validate=no",
        ]);
        pin_nrpt();
    }

    pub fn clear_dns(tun_name: &str) {
        clear_nrpt();
        let _ = run_netsh(&[
            "interface",
            "ipv4",
            "set",
            "dnsservers",
            &format!("name={tun_name}"),
            "source=dhcp",
        ]);
    }

    /// Catch-all NRPT so Win10/11 does not still ask the LAN resolver
    /// (adapter DNS alone is not enough). Idempotent for the watchdog.
    static NRPT_RULE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

    pub fn pin_nrpt() {
        let dns = crate::SERVER_TUN_IPV4.to_string();
        let mut slot = NRPT_RULE
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if slot.is_some() {
            return;
        }

        let script = format!(
            "Add-DnsClientNrptRule -Namespace '.' -NameServers '{dns}' | Out-Null; \
             (Get-DnsClientNrptRule | Where-Object {{ $_.NameServers -contains '{dns}' }} | \
              Select-Object -Last 1).Name"
        );

        let output = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output();

        if let Ok(output) = output {
            let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !name.is_empty() {
                *slot = Some(name);
            }
        }
    }

    pub fn clear_nrpt() {
        let mut slot = NRPT_RULE
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let Some(name) = slot.take() else {
            return;
        };

        let script = format!("Remove-DnsClientNrptRule -Name '{name}' -Force");
        let _ = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output();
    }

    pub fn teardown(server_ip: IpAddr, gateway: IpAddr, tun_name: &str) {
        clear_dns(tun_name);
        remove_ipv6_blackholes();
        let _ = run_route(&[
            "delete",
            "128.0.0.0",
            "mask",
            "128.0.0.0",
            super::TUNNEL_GATEWAY,
        ]);
        let _ = run_route(&[
            "delete",
            "0.0.0.0",
            "mask",
            "128.0.0.0",
            super::TUNNEL_GATEWAY,
        ]);
        let _ = run_route(&[
            "delete",
            &server_ip.to_string(),
            "mask",
            "255.255.255.255",
            &gateway.to_string(),
        ]);
    }

    fn run_netsh(args: &[&str]) -> io::Result<()> {
        let output = Command::new("netsh").args(args).output()?;

        if !output.status.success() {
            return Err(io::Error::other(format!(
                "netsh {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(())
    }

    fn run_route(args: &[&str]) -> io::Result<()> {
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
}

/// `ip route show default`: `default via 192.168.1.1 dev eth0 ...`
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_linux_default_iface(text: &str) -> Option<String> {
    let mut fields = text.split_whitespace();
    while let Some(field) = fields.next() {
        if field == "dev" {
            return fields.next().map(str::to_string);
        }
    }
    None
}

/// `route print -4` default line: `0.0.0.0  0.0.0.0  <gateway>  <iface-ip>  <metric>`.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn parse_windows_route_print_gateway(text: &str) -> Option<std::net::IpAddr> {
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 3 && cols[0] == "0.0.0.0" && cols[1] == "0.0.0.0" {
            if let Ok(gateway) = cols[2].parse::<std::net::IpAddr>()
                && !gateway.is_unspecified()
            {
                return Some(gateway);
            }
        }
    }

    None
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn parse_windows_route_print_iface_ipv4(text: &str) -> Option<std::net::Ipv4Addr> {
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 4 && cols[0] == "0.0.0.0" && cols[1] == "0.0.0.0" {
            if cols[2].parse::<std::net::IpAddr>().ok()?.is_unspecified() {
                continue;
            }
            if let Ok(ip) = cols[3].parse::<std::net::Ipv4Addr>()
                && !ip.is_unspecified()
                && !ip.is_loopback()
            {
                return Some(ip);
            }
        }
    }

    None
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn parse_netsh_interface_index(text: &str, tun_name: &str) -> Option<u32> {
    let want = tun_name.trim();
    if want.is_empty() {
        return None;
    }

    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let idx: u32 = match parts.next().and_then(|col| col.parse().ok()) {
            Some(idx) => idx,
            None => continue,
        };
        let _met = parts.next();
        let _mtu = parts.next();
        let _state = parts.next();
        let name = parts.collect::<Vec<_>>().join(" ");
        if name.eq_ignore_ascii_case(want) {
            return Some(idx);
        }
    }

    None
}

/// Current default interface name (`en0`, …) captured *before*
/// full-tunnel routes are installed — afterwards `route get default`
/// would report utun.
pub fn default_physical_interface() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        macos::default_interface().ok()
    }

    #[cfg(not(target_os = "macos"))]
    None
}

/// IPv4 of the current default interface — bind the QUIC socket
/// here so the kernel sources packets from the LAN NIC even if a
/// default route later points at utun.
pub fn default_outbound_ipv4() -> Option<std::net::Ipv4Addr> {
    #[cfg(target_os = "macos")]
    {
        let iface = macos::default_interface().ok()?;

        let output = std::process::Command::new("ipconfig")
            .args(["getifaddr", &iface])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        String::from_utf8(output.stdout).ok()?.trim().parse().ok()
    }

    #[cfg(target_os = "windows")]
    {
        let output = std::process::Command::new("route")
            .args(["print", "-4"])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        parse_windows_route_print_iface_ipv4(&String::from_utf8_lossy(&output.stdout))
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_windows_route_print_gateway() {
        let sample = "\
===========================================================================
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.50     25
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
";
        assert_eq!(
            parse_windows_route_print_gateway(sample),
            Some("192.168.1.1".parse().unwrap())
        );
        assert_eq!(
            parse_windows_route_print_iface_ipv4(sample),
            Some("192.168.1.50".parse().unwrap())
        );
    }

    #[test]
    fn parses_netsh_interface_index() {
        let sample = "\
Idx     Met         MTU          State                Name
  1      75  4294967295          connected            Loopback Pseudo-Interface 1
 12       5        1100          connected            payphone
";
        assert_eq!(parse_netsh_interface_index(sample, "payphone"), Some(12));
        assert_eq!(parse_netsh_interface_index(sample, "PAYPHONE"), Some(12));
        assert_eq!(parse_netsh_interface_index(sample, "missing"), None);
    }

    #[test]
    fn parses_linux_default_iface() {
        let sample = "default via 192.168.1.1 dev enp0s3 proto dhcp metric 100\n";
        assert_eq!(parse_linux_default_iface(sample).as_deref(), Some("enp0s3"));
    }
}
