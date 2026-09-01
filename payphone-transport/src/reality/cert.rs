use std::sync::Arc;

use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ED25519, SigningKey};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use tokio_rustls::TlsAcceptor;

use super::auth::{ct_eq, hmac_sha512};
use crate::https_front::HTTP_ALPN;

const ED25519_SPKI_PREFIX: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

/// Ephemeral Ed25519 leaf whose X.509 signature is HMAC-SHA512(AuthKey, pubkey),
/// matching XTLS/REALITY (`h.Sum(signedCert[:len-64])`).
pub fn mint_hmac_leaf(
    auth_key: &[u8; 32],
    server_name: &str,
) -> Result<(Vec<u8>, KeyPair), Box<dyn std::error::Error + Send + Sync>> {
    let key_pair = KeyPair::generate_for(&PKCS_ED25519).map_err(|error| error.to_string())?;
    let mut params =
        CertificateParams::new(vec![server_name.to_string()]).map_err(|error| error.to_string())?;
    params
        .distinguished_name
        .push(DnType::CommonName, server_name.to_string());
    let cert = params
        .self_signed(&key_pair)
        .map_err(|error| error.to_string())?;
    let mut der = cert.der().as_ref().to_vec();

    if der.len() < 64 {
        return Err("REALITY HMAC cert is too short".into());
    }

    let public = ed25519_pubkey_from_der(&der).ok_or("REALITY HMAC cert has no Ed25519 key")?;
    let mac = hmac_sha512(auth_key, &public);
    let end = der.len();
    der[end - 64..].copy_from_slice(&mac);

    Ok((der, key_pair))
}

pub fn mint_hmac_certificate(
    auth_key: &[u8; 32],
    server_name: &str,
) -> Result<
    (CertificateDer<'static>, PrivateKeyDer<'static>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let (der, key_pair) = mint_hmac_leaf(auth_key, server_name)?;
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    Ok((CertificateDer::from(der), key))
}

pub fn sign_hmac_leaf(key_pair: &KeyPair, message: &[u8]) -> Result<Vec<u8>, String> {
    key_pair.sign(message).map_err(|error| error.to_string())
}

pub fn verify_hmac_certificate(auth_key: &[u8; 32], der: &[u8]) -> bool {
    if der.len() < 64 {
        return false;
    }

    let Some(public) = ed25519_pubkey_from_der(der) else {
        return false;
    };

    let mac = hmac_sha512(auth_key, &public);
    ct_eq(&mac, &der[der.len() - 64..])
}

pub fn hmac_tls_acceptor(
    auth_key: &[u8; 32],
    server_name: &str,
) -> Result<TlsAcceptor, Box<dyn std::error::Error + Send + Sync>> {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites = vec![rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256];
    let _ = provider.clone().install_default();
    let (certificate, private_key) = mint_hmac_certificate(auth_key, server_name)?;
    let mut config = ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| error.to_string())?
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key)
        .map_err(|error| error.to_string())?;
    config.alpn_protocols = vec![HTTP_ALPN.to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn ed25519_pubkey_from_der(der: &[u8]) -> Option<[u8; 32]> {
    der.windows(ED25519_SPKI_PREFIX.len() + 32)
        .find_map(|window| {
            window
                .starts_with(ED25519_SPKI_PREFIX)
                .then(|| window[ED25519_SPKI_PREFIX.len()..].try_into().ok())
                .flatten()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_signature_roundtrip() {
        let auth_key = [0x42u8; 32];
        let (cert, _key) = mint_hmac_certificate(&auth_key, "www.microsoft.com").unwrap();
        assert!(verify_hmac_certificate(&auth_key, cert.as_ref()));
        assert!(!verify_hmac_certificate(&[0u8; 32], cert.as_ref()));
    }
}
