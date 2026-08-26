use std::{fs, path::Path};

use rcgen::{CertifiedKey, generate_simple_self_signed};

/// DEV certificate.
///
/// Пока клиент и сервер запускаются
/// из корня PAYPHONE проекта.
pub const CERT_PATH: &str = "dev-certs/payphone-cert.der";

/// Private key сервера.
pub const KEY_PATH: &str = "dev-certs/payphone-key.der";

/// DNS имя PAYPHONE server,
/// записанное внутрь certificate.
pub const SERVER_NAME: &str = "localhost";

/// Создаёт TLS identity сервера,
/// если её ещё нет.
///
/// После первого запуска появятся:
///
/// dev-certs/
/// ├── payphone-cert.der
/// └── payphone-key.der
pub fn ensure_dev_identity() -> Result<(), Box<dyn std::error::Error>> {
    //
    // Если оба файла уже существуют,
    // ничего генерировать не нужно.
    //
    if Path::new(CERT_PATH).exists() && Path::new(KEY_PATH).exists() {
        return Ok(());
    }

    //
    // Создаём папку.
    //
    fs::create_dir_all("dev-certs")?;

    //
    // Генерируем:
    //
    // certificate
    // +
    // private key
    //
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec![SERVER_NAME.to_string()])?;

    //
    // Certificate — публичная часть.
    //
    // Её будет знать клиент.
    //
    fs::write(CERT_PATH, cert.der().as_ref())?;

    //
    // Private key — секрет сервера.
    //
    // Клиент его НЕ получает.
    //
    fs::write(KEY_PATH, signing_key.serialize_der())?;

    println!("Generated PAYPHONE TLS identity");

    println!("Certificate: {}", CERT_PATH);

    println!("Private key: {}", KEY_PATH);

    Ok(())
}
