use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use quinn::{ClientConfig, Endpoint, EndpointConfig, default_runtime};

use rustls::{RootCertStore, pki_types::CertificateDer};

use crate::{
    identity::CERT_PATH, obfuscated_socket::ObfuscatedSocket, obfuscation::ObfuscationKey,
};

/// Создаёт PAYPHONE QUIC client endpoint.
///
/// `obfuscation_key` должен быть одинаковым
/// на клиенте и на сервере — см. `payphone_transport::obfuscation`.
///
/// `dev_mode` включает диагностическое логирование в
/// `ObfuscatedSocket` (см. его документацию).
pub fn create_client_endpoint(
    obfuscation_key: ObfuscationKey,
    dev_mode: bool,
    bind_ip: Option<IpAddr>,
    bind_iface: Option<&str>,
) -> Result<Endpoint, Box<dyn std::error::Error>> {
    //
    // Читаем certificate PAYPHONE server.
    //
    // Если сервер ни разу не запускался,
    // файла ещё не будет.
    //
    let certificate_bytes = fs::read(CERT_PATH)?;

    let certificate = CertificateDer::from(certificate_bytes);

    //
    // RootCertStore —
    // список сертификатов,
    // которым доверяет клиент.
    //
    let mut roots = RootCertStore::empty();

    //
    // Добавляем именно наш
    // PAYPHONE certificate.
    //
    roots.add(certificate)?;

    //
    // Создаём Quinn ClientConfig.
    //
    let mut client_config = ClientConfig::with_root_certificates(Arc::new(roots))?;

    client_config.transport_config(crate::vpn_transport());

    //
    // :0 означает:
    //
    // "операционная система,
    // выбери свободный UDP port".
    //
    let bind_address = SocketAddr::new(bind_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), 0);

    //
    // Сами биндим UDP socket и оборачиваем его в ObfuscatedSocket —
    // симметрично серверной стороне.
    //
    let socket = std::net::UdpSocket::bind(bind_address)?;

    crate::tune_udp_buffers(&socket);

    //
    // Pin UDP to the LAN NIC. Binding the source IP is not enough:
    // once 0.0.0.0/1 points at utun, the kernel still egresses
    // unscoped datagrams into the tunnel. IP_BOUND_IF forces en0
    // even if macOS has just rebuilt the routing table.
    //
    #[cfg(target_os = "macos")]
    if let Some(iface) = bind_iface {
        if let Err(error) = macos_iface::bind_udp_to_iface(&socket, iface) {
            eprintln!("PAYPHONE: IP_BOUND_IF {iface} failed ({error})");
        }
    }

    #[cfg(not(target_os = "macos"))]
    let _ = bind_iface;

    let runtime = default_runtime()
        .ok_or_else(|| "no async runtime found for PAYPHONE QUIC endpoint".to_string())?;

    let async_socket = runtime.wrap_udp_socket(socket)?;

    let obfuscated_socket = Arc::new(ObfuscatedSocket::new(
        async_socket,
        obfuscation_key,
        dev_mode,
    ));

    let mut endpoint = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        None,
        obfuscated_socket,
        runtime,
    )?;

    endpoint.set_default_client_config(client_config);

    Ok(endpoint)
}

#[cfg(target_os = "macos")]
mod macos_iface {
    use std::{io, net::UdpSocket, os::unix::io::AsRawFd};

    pub fn bind_udp_to_iface(socket: &UdpSocket, iface: &str) -> io::Result<()> {
        let c_name = std::ffi::CString::new(iface).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "interface name contains NUL")
        })?;

        let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };

        if index == 0 {
            return Err(io::Error::last_os_error());
        }

        let fd = socket.as_raw_fd();

        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_BOUND_IF,
                (&index as *const u32).cast(),
                std::mem::size_of_val(&index) as libc::socklen_t,
            )
        };

        if result != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }
}
