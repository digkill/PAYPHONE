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
    let client_config = ClientConfig::with_root_certificates(Arc::new(roots))?;

    //
    // :0 означает:
    //
    // "операционная система,
    // выбери свободный UDP port".
    //
    let bind_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

    //
    // Сами биндим UDP socket и оборачиваем его в ObfuscatedSocket —
    // симметрично серверной стороне.
    //
    let socket = std::net::UdpSocket::bind(bind_address)?;

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
