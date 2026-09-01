//! Shared TLS identity for QUIC and the HTTPS front.
//!
//! File certs reload on mtime (certbot / Coolify volume). When
//! `PAYPHONE_TLS_DOMAIN` is set, Let's Encrypt issues a public leaf
//! via TLS-ALPN-01 on TCP 443; QUIC picks it up through the same
//! resolver once ACME finishes.

use std::{
    fmt, fs,
    sync::{Arc, Mutex},
    time::SystemTime,
};

use rustls::{
    ServerConfig,
    crypto::ring::sign::any_supported_type,
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use tokio_rustls::TlsAcceptor;

use crate::{
    https_front::HTTP_ALPN,
    identity::{
        ServerTlsConfig, ensure_server_identity, load_certificates, load_private_key,
        looks_like_public_dns_name,
    },
};

const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";

fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

struct ReloadingFileResolver {
    tls: ServerTlsConfig,
    cached: Mutex<Option<CachedCert>>,
}

struct CachedCert {
    key: Arc<CertifiedKey>,
    cert_mtime: Option<SystemTime>,
    key_mtime: Option<SystemTime>,
}

impl ReloadingFileResolver {
    fn new(tls: ServerTlsConfig) -> Self {
        Self {
            tls,
            cached: Mutex::new(None),
        }
    }

    fn current(&self) -> Option<Arc<CertifiedKey>> {
        let cert_mtime = fs::metadata(&self.tls.cert_path)
            .and_then(|meta| meta.modified())
            .ok();
        let key_mtime = fs::metadata(&self.tls.key_path)
            .and_then(|meta| meta.modified())
            .ok();

        let mut guard = self
            .cached
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());

        let stale = match guard.as_ref() {
            None => true,
            Some(cached) => cached.cert_mtime != cert_mtime || cached.key_mtime != key_mtime,
        };

        if stale {
            match load_certified_key(&self.tls) {
                Ok(key) => {
                    *guard = Some(CachedCert {
                        key: Arc::clone(&key),
                        cert_mtime,
                        key_mtime,
                    });
                    Some(key)
                }
                Err(error) => {
                    if let Some(cached) = guard.as_ref() {
                        eprintln!(
                            "PAYPHONE TLS reload failed ({error}); keeping previous certificate"
                        );
                        Some(Arc::clone(&cached.key))
                    } else {
                        None
                    }
                }
            }
        } else {
            guard.as_ref().map(|cached| Arc::clone(&cached.key))
        }
    }
}

impl fmt::Debug for ReloadingFileResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReloadingFileResolver")
            .field("cert", &self.tls.cert_path)
            .finish_non_exhaustive()
    }
}

impl ResolvesServerCert for ReloadingFileResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.current()
    }
}

struct CompositeResolver {
    acme: Option<Arc<rustls_acme::ResolvesServerCertAcme>>,
    file: ReloadingFileResolver,
}

impl fmt::Debug for CompositeResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompositeResolver")
            .field("acme", &self.acme.is_some())
            .finish_non_exhaustive()
    }
}

impl ResolvesServerCert for CompositeResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if let Some(acme) = &self.acme {
            if let Some(key) = acme.resolve(client_hello) {
                return Some(key);
            }
        }

        self.file.current()
    }
}

fn load_certified_key(
    tls: &ServerTlsConfig,
) -> Result<Arc<CertifiedKey>, Box<dyn std::error::Error>> {
    ensure_server_identity(tls)?;
    let certs = load_certificates(&tls.cert_path)?;
    let key = load_private_key(&tls.key_path)?;
    let signing = any_supported_type(&key)?;
    Ok(Arc::new(CertifiedKey::new(certs, signing)))
}

/// QUIC + TCP acceptors that share one certificate (file and/or ACME).
#[derive(Clone)]
pub struct ServerTlsRuntime {
    pub tls: ServerTlsConfig,
    pub acceptor: TlsAcceptor,
    pub acme_challenge: Option<TlsAcceptor>,
    resolver: Arc<dyn ResolvesServerCert>,
}

impl ServerTlsRuntime {
    pub fn start(tls: &ServerTlsConfig) -> Result<Self, Box<dyn std::error::Error>> {
        ensure_crypto_provider();
        ensure_server_identity(tls)?;

        let file = ReloadingFileResolver::new(tls.clone());
        if file.current().is_none() {
            return Err("TLS certificate could not be loaded".into());
        }

        let mut acme_resolver = None;
        let mut acme_challenge = None;

        if tls.acme_enabled() {
            let domain = tls.acme_domain.clone().expect("acme_enabled");
            let started = start_acme(tls, &domain)?;
            acme_resolver = Some(started.resolver);
            acme_challenge = Some(started.challenge);
            println!(
                "PAYPHONE TLS: Let's Encrypt {} ({}, cache {})",
                domain,
                if tls.acme_staging {
                    "staging — browsers will not trust it"
                } else {
                    "production TLS-ALPN-01"
                },
                tls.acme_dir.display()
            );
            println!("PAYPHONE TLS: client --sni {domain} --tls-ca system");
        }

        let resolver: Arc<dyn ResolvesServerCert> = Arc::new(CompositeResolver {
            acme: acme_resolver,
            file,
        });

        let mut tcp = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::clone(&resolver));
        tcp.alpn_protocols = vec![HTTP_ALPN.to_vec()];

        Ok(Self {
            tls: tls.clone(),
            acceptor: TlsAcceptor::from(Arc::new(tcp)),
            acme_challenge,
            resolver,
        })
    }

    pub fn quinn_server_config(&self) -> Result<quinn::ServerConfig, Box<dyn std::error::Error>> {
        ensure_crypto_provider();

        let mut crypto = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_cert_resolver(Arc::clone(&self.resolver));
        crypto.max_early_data_size = u32::MAX;

        let quic = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
            .map_err(|error| format!("QUIC TLS: {error}"))?;
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(quic));
        server.transport_config(crate::vpn_transport());
        Ok(server)
    }
}

struct AcmeStarted {
    resolver: Arc<rustls_acme::ResolvesServerCertAcme>,
    challenge: TlsAcceptor,
}

fn start_acme(
    tls: &ServerTlsConfig,
    domain: &str,
) -> Result<AcmeStarted, Box<dyn std::error::Error>> {
    if !looks_like_public_dns_name(domain) {
        return Err(format!("PAYPHONE_TLS_DOMAIN {domain} is not a public DNS name").into());
    }

    fs::create_dir_all(&tls.acme_dir)?;

    let email = tls
        .acme_email
        .clone()
        .unwrap_or_else(|| format!("mailto:admin@{domain}"));
    let email = if email.starts_with("mailto:") {
        email
    } else {
        format!("mailto:{email}")
    };

    let mut state = rustls_acme::AcmeConfig::new([domain])
        .contact_push(email)
        .directory_lets_encrypt(!tls.acme_staging)
        .cache(rustls_acme::caches::DirCache::new(tls.acme_dir.clone()))
        .state();

    let resolver = state.resolver();

    let mut challenge_cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::clone(&resolver) as Arc<dyn ResolvesServerCert>);
    challenge_cfg.alpn_protocols = vec![ACME_TLS_ALPN.to_vec()];
    let challenge = TlsAcceptor::from(Arc::new(challenge_cfg));

    tokio::spawn(async move {
        use futures_util::StreamExt;

        loop {
            match state.next().await {
                Some(Ok(ok)) => println!("PAYPHONE ACME: {ok:?}"),
                Some(Err(err)) => eprintln!("PAYPHONE ACME: {err:?}"),
                None => break,
            }
        }
    });

    Ok(AcmeStarted {
        resolver,
        challenge,
    })
}
