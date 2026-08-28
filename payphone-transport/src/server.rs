use std::{fs, net::SocketAddr, sync::Arc};

use quinn::{Endpoint, EndpointConfig, ServerConfig, default_runtime};

use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use crate::{
    identity::{CERT_PATH, KEY_PATH, ensure_dev_identity},
    obfuscated_socket::ObfuscatedSocket,
    obfuscation::ObfuscationKey,
};

/// Создаёт QUIC endpoint PAYPHONE server.
///
/// Endpoint — это главный объект Quinn.
///
/// Он содержит:
///
/// UDP socket
/// QUIC state
/// TLS state
///
/// `obfuscation_key` должен быть одинаковым
/// на сервере и на клиенте — см. `payphone_transport::obfuscation`.
///
/// `dev_mode` включает диагностическое логирование в
/// `ObfuscatedSocket` (см. его документацию).
pub fn create_server_endpoint(
    address: SocketAddr,
    obfuscation_key: ObfuscationKey,
    dev_mode: bool,
) -> Result<Endpoint, Box<dyn std::error::Error>> {
    //
    // Сначала гарантируем,
    // что certificate/key существуют.
    //
    ensure_dev_identity()?;

    //
    // Читаем certificate с диска.
    //
    let certificate_bytes = fs::read(CERT_PATH)?;

    //
    // Читаем private key.
    //
    let private_key_bytes = fs::read(KEY_PATH)?;

    //
    // Vec<u8>
    //
    // превращаем в тип,
    // понятный rustls.
    //
    let certificate = CertificateDer::from(certificate_bytes);

    let private_key = PrivatePkcs8KeyDer::from(private_key_bytes);

    //
    // Создаём QUIC server config.
    //
    // TLS уже является частью QUIC.
    //
    let mut server_config = ServerConfig::with_single_cert(vec![certificate], private_key.into())?;

    server_config.transport_config(crate::vpn_transport());

    //
    // Сами биндим UDP socket и оборачиваем его в ObfuscatedSocket,
    // чтобы прозрачно для quinn обфусцировать каждую датаграмму.
    //
    let socket = std::net::UdpSocket::bind(address)?;

    crate::tune_udp_buffers(&socket);

    let runtime = default_runtime()
        .ok_or_else(|| "no async runtime found for PAYPHONE QUIC endpoint".to_string())?;

    let async_socket = runtime.wrap_udp_socket(socket)?;

    let obfuscated_socket = Arc::new(ObfuscatedSocket::new(
        async_socket,
        obfuscation_key,
        dev_mode,
    ));

    let endpoint = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        Some(server_config),
        obfuscated_socket,
        runtime,
    )?;

    Ok(endpoint)
}
