use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use quinn::{ClientConfig, Endpoint};

use rustls::{RootCertStore, pki_types::CertificateDer};

use crate::identity::CERT_PATH;

/// Создаёт PAYPHONE QUIC client endpoint.
pub fn create_client_endpoint() -> Result<Endpoint, Box<dyn std::error::Error>> {
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

    let mut endpoint = Endpoint::client(bind_address)?;

    endpoint.set_default_client_config(client_config);

    Ok(endpoint)
}
