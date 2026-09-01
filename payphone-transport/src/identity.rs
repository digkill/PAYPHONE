use std::{
    fs,
    io::Cursor,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};

pub const CERT_PATH: &str = "dev-certs/payphone-cert.der";

pub const KEY_PATH: &str = "dev-certs/payphone-key.der";

/// Default SNI / certificate DNS name for the generated identity.
pub const SERVER_NAME: &str = "localhost";

fn generation_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    LOCK.get_or_init(|| Mutex::new(()))
}

/// Where the server reads its certificate and (optionally) what
/// names to bake into a generated self-signed identity.
#[derive(Clone, Debug)]
pub struct ServerTlsConfig {
    pub cert_path: PathBuf,

    pub key_path: PathBuf,

    pub sans: Vec<String>,

    /// Public DNS name. When set and cert/key are still the default
    /// self-signed paths, the server obtains a Let's Encrypt leaf
    /// via TLS-ALPN-01 on the HTTPS front (TCP 443).
    pub acme_domain: Option<String>,

    pub acme_email: Option<String>,

    pub acme_dir: PathBuf,

    /// Let's Encrypt staging (untrusted by browsers). Default off.
    pub acme_staging: bool,
}

impl Default for ServerTlsConfig {
    fn default() -> Self {
        Self {
            cert_path: PathBuf::from(CERT_PATH),
            key_path: PathBuf::from(KEY_PATH),
            sans: vec![SERVER_NAME.to_string()],
            acme_domain: None,
            acme_email: None,
            acme_dir: default_acme_dir(),
            acme_staging: false,
        }
    }
}

pub fn default_acme_dir() -> PathBuf {
    if Path::new("/app/state").is_dir() {
        PathBuf::from("/app/state/acme")
    } else {
        PathBuf::from("dev-certs/acme")
    }
}

impl ServerTlsConfig {
    pub fn from_env() -> Self {
        Self {
            cert_path: env_path("PAYPHONE_TLS_CERT", CERT_PATH),

            key_path: env_path("PAYPHONE_TLS_KEY", KEY_PATH),

            sans: parse_sans(std::env::var("PAYPHONE_TLS_SAN").ok()),
            acme_domain: std::env::var("PAYPHONE_TLS_DOMAIN")
                .ok()
                .filter(|value| !value.is_empty()),
            acme_email: std::env::var("PAYPHONE_ACME_EMAIL")
                .ok()
                .filter(|value| !value.is_empty()),
            acme_dir: std::env::var("PAYPHONE_ACME_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| default_acme_dir()),
            acme_staging: matches!(
                std::env::var("PAYPHONE_ACME_STAGING")
                    .unwrap_or_default()
                    .to_ascii_lowercase()
                    .as_str(),
                "1" | "true" | "on" | "yes"
            ),
        }
    }

    pub fn uses_default_paths(&self) -> bool {
        self.cert_path == Path::new(CERT_PATH) && self.key_path == Path::new(KEY_PATH)
    }

    /// ACME on the default self-signed paths. Mounted PEM wins over ACME.
    pub fn acme_enabled(&self) -> bool {
        self.acme_domain
            .as_ref()
            .is_some_and(|name| looks_like_public_dns_name(name))
            && self.uses_default_paths()
    }

    /// Hostnames we should terminate locally (landing / ACME / our cert)
    /// instead of REALITY-splicing to dest.
    pub fn local_hostnames(&self) -> Vec<String> {
        let mut names = self.sans.clone();

        if let Some(domain) = &self.acme_domain {
            names.push(domain.clone());
        }

        names.sort();
        names.dedup();
        names.into_iter().filter(|name| !name.is_empty()).collect()
    }
}

/// How the client authenticates the server certificate.
#[derive(Clone, Debug)]
pub struct ClientTlsConfig {
    /// SNI and rustls server name. Must match a SAN on the cert.
    pub server_name: String,

    /// Pinned leaf (or CA) when not using the public WebPKI roots.
    pub pin_path: PathBuf,

    /// Trust the Mozilla/webpki root store instead of a pin file.
    /// Use this with a Let's Encrypt (or other public) certificate.
    pub use_webpki: bool,

    /// Xray-compatible REALITY on the TCP path. `None` = ordinary rustls.
    pub reality: Option<crate::reality::RealityClientConfig>,
}

impl Default for ClientTlsConfig {
    fn default() -> Self {
        Self {
            server_name: SERVER_NAME.to_string(),

            pin_path: PathBuf::from(CERT_PATH),

            use_webpki: false,

            reality: None,
        }
    }
}

impl ClientTlsConfig {
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(name) = std::env::var("PAYPHONE_SERVER_NAME") {
            if !name.is_empty() {
                config.server_name = name;
            }
        }

        if let Ok(path) = std::env::var("PAYPHONE_TLS_PIN") {
            config.pin_path = PathBuf::from(path);
        } else if let Ok(path) = std::env::var("PAYPHONE_TLS_CERT") {
            // Same env name as the server: a client copy of the leaf.
            config.pin_path = PathBuf::from(path);
        }

        if let Ok(value) = std::env::var("PAYPHONE_TLS_CA") {
            config.use_webpki = matches!(
                value.to_ascii_lowercase().as_str(),
                "system" | "webpki" | "public" | "1" | "true"
            );
        }

        config
    }
}

/// Host part of `host:port` or `[v6]:port`. `None` if empty.
pub fn hostname_from_addr(addr: &str) -> Option<String> {
    let addr = addr.trim();

    if addr.is_empty() {
        return None;
    }

    if let Some(rest) = addr.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = rest[..end].trim();
        return (!host.is_empty()).then(|| host.to_string());
    }

    match addr.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.chars().all(|ch| ch.is_ascii_digit()) => {
            Some(host.to_string())
        }
        _ => Some(addr.to_string()),
    }
}

/// A name browsers and Let's Encrypt will treat as a real DNS name.
pub fn looks_like_public_dns_name(name: &str) -> bool {
    let name = name.trim().trim_end_matches('.');

    if name.is_empty() || name.eq_ignore_ascii_case(SERVER_NAME) {
        return false;
    }

    if name.parse::<IpAddr>().is_ok() {
        return false;
    }

    name.contains('.')
}

pub fn parse_sans(value: Option<String>) -> Vec<String> {
    let names: Vec<String> = value
        .unwrap_or_default()
        .split(',')
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .collect();

    if names.is_empty() {
        vec![SERVER_NAME.to_string()]
    } else {
        names
    }
}

fn env_path(var: &str, default: &str) -> PathBuf {
    std::env::var(var)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(default))
}

pub fn looks_like_pem(bytes: &[u8]) -> bool {
    bytes.starts_with(b"-----BEGIN") || bytes.windows(11).any(|w| w == b"-----BEGIN")
}

pub fn load_certificates(
    path: &Path,
) -> Result<Vec<CertificateDer<'static>>, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)
        .map_err(|error| format!("cannot read TLS certificate {}: {error}", path.display()))?;

    if looks_like_pem(&bytes) {
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut Cursor::new(&bytes))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("invalid certificate PEM {}: {error}", path.display()))?;

        if certs.is_empty() {
            return Err(format!("no certificates in {}", path.display()).into());
        }

        Ok(certs)
    } else {
        Ok(vec![CertificateDer::from(bytes)])
    }
}

pub fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)
        .map_err(|error| format!("cannot read TLS private key {}: {error}", path.display()))?;

    if looks_like_pem(&bytes) {
        rustls_pemfile::private_key(&mut Cursor::new(&bytes))
            .map_err(|error| format!("invalid private key PEM {}: {error}", path.display()))?
            .ok_or_else(|| format!("no private key in {}", path.display()).into())
    } else {
        Ok(PrivatePkcs8KeyDer::from(bytes).into())
    }
}

/// Creates the self-signed identity when using the default paths
/// and the files are missing. Custom cert/key paths are never invented.
pub fn ensure_server_identity(config: &ServerTlsConfig) -> Result<(), Box<dyn std::error::Error>> {
    let _guard = generation_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());

    if config.cert_path.exists() && config.key_path.exists() {
        return Ok(());
    }

    if !config.uses_default_paths() {
        return Err(format!(
            "TLS certificate {} or key {} is missing",
            config.cert_path.display(),
            config.key_path.display()
        )
        .into());
    }

    if let Some(parent) = config.cert_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut sans = config.sans.clone();

    if let Some(domain) = &config.acme_domain {
        if looks_like_public_dns_name(domain)
            && !sans.iter().any(|name| name.eq_ignore_ascii_case(domain))
        {
            sans.push(domain.clone());
        }
    }

    let CertifiedKey { cert, signing_key } = generate_simple_self_signed(sans.clone())?;

    fs::write(&config.cert_path, cert.der().as_ref())?;

    fs::write(&config.key_path, signing_key.serialize_der())?;

    println!("Generated PAYPHONE TLS identity");

    println!("Certificate: {}", config.cert_path.display());

    println!("Private key: {}", config.key_path.display());

    println!("SAN: {}", config.sans.join(", "));

    Ok(())
}

pub fn ensure_dev_identity() -> Result<(), Box<dyn std::error::Error>> {
    ensure_server_identity(&ServerTlsConfig::from_env())
}

pub fn load_server_tls(
    config: &ServerTlsConfig,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Box<dyn std::error::Error>> {
    ensure_server_identity(config)?;

    Ok((
        load_certificates(&config.cert_path)?,
        load_private_key(&config.key_path)?,
    ))
}

pub fn client_root_store(
    config: &ClientTlsConfig,
) -> Result<RootCertStore, Box<dyn std::error::Error>> {
    let mut roots = RootCertStore::empty();

    if config.use_webpki {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let pin_exists = config.pin_path.exists();

    if pin_exists {
        for certificate in load_certificates(&config.pin_path)? {
            roots.add(certificate)?;
        }
    } else if !config.use_webpki {
        return Err(format!(
            "cannot read pinned TLS certificate {}",
            config.pin_path.display()
        )
        .into());
    }

    if roots.is_empty() {
        return Err("TLS trust store is empty".into());
    }

    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_is_detected() {
        assert!(looks_like_pem(
            b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
        ));

        assert!(!looks_like_pem(&[0x30, 0x82, 0x01, 0x5d]));
    }

    #[test]
    fn default_san_is_localhost() {
        assert_eq!(parse_sans(None), vec!["localhost"]);

        assert_eq!(
            parse_sans(Some(" vpn.example.com , localhost ".into())),
            vec!["vpn.example.com", "localhost"]
        );
    }

    #[test]
    fn hostname_from_addr_splits_port() {
        assert_eq!(
            hostname_from_addr("vpn.example.com:443").as_deref(),
            Some("vpn.example.com")
        );
        assert_eq!(
            hostname_from_addr("127.0.0.1:40404").as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(hostname_from_addr("[::1]:443").as_deref(), Some("::1"));
        assert_eq!(
            hostname_from_addr("vpn.example.com").as_deref(),
            Some("vpn.example.com")
        );
    }

    #[test]
    fn public_dns_name_skips_localhost_and_ips() {
        assert!(looks_like_public_dns_name("vpn.example.com"));
        assert!(looks_like_public_dns_name(
            "maekedpjbsakslcdmtzc7qaw.201.51.24.102.sslip.io"
        ));
        assert!(!looks_like_public_dns_name("localhost"));
        assert!(!looks_like_public_dns_name("127.0.0.1"));
        assert!(!looks_like_public_dns_name("201.51.24.102"));
    }
}
