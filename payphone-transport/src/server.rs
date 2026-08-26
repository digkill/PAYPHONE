use std::{fs, net::SocketAddr};

use quinn::{Endpoint, ServerConfig};

use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use crate::identity::{CERT_PATH, KEY_PATH, ensure_dev_identity};

/// Создаёт QUIC endpoint PAYPHONE server.
///
/// Endpoint — это главный объект Quinn.
///
/// Он содержит:
///
/// UDP socket
/// QUIC state
/// TLS state
pub fn create_server_endpoint(address: SocketAddr) -> Result<Endpoint, Box<dyn std::error::Error>> {
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
    let server_config = ServerConfig::with_single_cert(vec![certificate], private_key.into())?;

    //
    // Создаём серверный Endpoint.
    //
    let endpoint = Endpoint::server(server_config, address)?;

    Ok(endpoint)
}
