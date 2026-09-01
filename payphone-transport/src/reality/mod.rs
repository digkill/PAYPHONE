//! Xray-compatible REALITY camouflage on TCP 443, PAYPHONE inside TLS.
//!
//! Unauthorized ClientHellos are spliced to `dest` (a real TLS 1.3 site).
//! A ClientHello whose `session_id` decrypts with the X25519/HKDF/AES-GCM
//! scheme from XTLS/Xray is accepted. The server then presents an
//! ephemeral Ed25519 certificate whose X.509 signature is
//! HMAC-SHA512(AuthKey, pubkey) — the same check Xray's
//! `VerifyPeerCertificate` uses. Inner frames stay PAYPHONE, not VLESS.
//!
//! TLS 1.3 encrypts the certificate; probes never see it. The authenticated
//! ClientHello mimics Chrome 131 (GREASE, ECH, real ML-KEM-768 + X25519). After auth the
//! server dials dest, copies dest's ServerHello, patches the X25519 key_share,
//! and matches dest's encrypted record sizes (handshake + post-handshake dummies).

mod auth;
mod cert;
mod hello;
mod keys;
mod record_detect;
mod splice;
mod suite;
mod tls13;

pub use auth::{open_session_id, seal_session_id};
pub use cert::{hmac_tls_acceptor, mint_hmac_certificate, verify_hmac_certificate};
pub use hello::{ClientHelloView, ServerHelloView, handshake_from_record};
pub use keys::{RealityKeypair, generate_keypair, parse_32_bytes, parse_short_id, parse_short_ids};
pub use splice::{DestFlight, PrefixedStream, RealityAccept, accept, read_tls_record};
pub use tls13::{Tls13Client, Tls13Stream};

use std::time::Duration;

use crate::reality::auth::{reality_auth_key, x25519_shared};

const DEFAULT_MAX_TIME_DIFF: Duration = Duration::from_secs(120);

/// PAYPHONE 0.2.0 in the Xray version triplet (bytes 0..3 of session_id).
pub const CLIENT_VERSION: [u8; 3] = [0, 2, 0];

#[derive(Clone, Debug)]
pub struct RealityClientConfig {
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],
    pub server_name: String,
}

#[derive(Clone, Debug)]
pub struct RealityServerConfig {
    pub dest: String,
    pub private_key: [u8; 32],
    pub short_ids: Vec<[u8; 8]>,
    pub server_names: Vec<String>,
    /// SNI we terminate ourselves (landing / Let's Encrypt) instead of dest.
    pub local_names: Vec<String>,
    pub max_time_diff: Duration,
    /// Post-handshake `0x17` sizes per ALPN class: none / http/1.1 / h2.
    pub post_handshake: std::sync::Arc<std::sync::Mutex<[Vec<usize>; 3]>>,
}

impl RealityServerConfig {
    pub fn new(
        dest: String,
        private_key: [u8; 32],
        short_ids: Vec<[u8; 8]>,
    ) -> Result<Self, String> {
        if dest.is_empty() {
            return Err("PAYPHONE_REALITY_DEST is empty".into());
        }

        if short_ids.is_empty() {
            return Err("PAYPHONE_REALITY_SHORT_ID is empty".into());
        }

        let host = dest_host(&dest)?;

        Ok(Self {
            dest,
            private_key,
            short_ids,
            server_names: vec![host],
            local_names: Vec::new(),
            max_time_diff: DEFAULT_MAX_TIME_DIFF,
            post_handshake: std::sync::Arc::new(std::sync::Mutex::new([
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ])),
        })
    }

    pub fn post_handshake_lens(&self) -> Vec<usize> {
        self.post_handshake_lens_for(2)
    }

    pub fn post_handshake_lens_for(&self, alpn_class: u8) -> Vec<usize> {
        let idx = usize::from(alpn_class).min(2);
        self.post_handshake
            .lock()
            .map(|guard| guard[idx].clone())
            .unwrap_or_default()
    }

    /// Background dest handshake to learn post-handshake `0x17` sizes (Xray).
    pub fn spawn_post_handshake_probe(&self) {
        let dest = self.dest.clone();
        let sni = self
            .server_names
            .first()
            .cloned()
            .unwrap_or_else(|| dest_host(&dest).unwrap_or_default());
        let cache = std::sync::Arc::clone(&self.post_handshake);

        for alpn in 0..3u8 {
            let dest = dest.clone();
            let sni = sni.clone();
            let cache = std::sync::Arc::clone(&cache);
            tokio::spawn(async move {
                let lens =
                    record_detect::probe_post_handshake_records_alpn(&dest, &sni, alpn).await;
                if let Ok(mut guard) = cache.lock() {
                    guard[usize::from(alpn)] = lens;
                }
            });
        }
    }
}

pub fn dest_host(dest: &str) -> Result<String, String> {
    let dest = dest.trim();

    if dest.is_empty() {
        return Err("REALITY dest is empty".into());
    }

    if let Some(stripped) = dest.strip_prefix('[') {
        let end = stripped
            .find(']')
            .ok_or_else(|| "invalid REALITY dest: missing ]".to_string())?;

        return Ok(stripped[..end].to_string());
    }

    match dest.rsplit_once(':') {
        Some((host, _)) if !host.is_empty() => Ok(host.to_string()),
        _ => Ok(dest.to_string()),
    }
}

pub fn authenticate(
    record: &[u8],
    config: &RealityServerConfig,
) -> Result<AuthenticatedHello, AuthError> {
    let view = ClientHelloView::parse(record).ok_or(AuthError::NotClientHello)?;

    if view.session_id.len() != 32 {
        return Err(AuthError::Rejected);
    }

    if !config.server_names.is_empty() {
        let sni = view.sni.as_deref().unwrap_or("");

        if !config
            .server_names
            .iter()
            .any(|name| name.eq_ignore_ascii_case(sni))
        {
            return Err(AuthError::Rejected);
        }
    }

    let Some(peer) = view.x25519_public else {
        return Err(AuthError::Rejected);
    };

    let handshake = handshake_from_record(record).ok_or(AuthError::NotClientHello)?;

    let plain = open_session_id(
        &config.private_key,
        &peer,
        &view.random,
        &view.session_id,
        handshake,
    )
    .ok_or(AuthError::Rejected)?;

    let short_id: [u8; 8] = plain[8..16].try_into().map_err(|_| AuthError::Rejected)?;

    if !config.short_ids.iter().any(|id| id == &short_id) {
        return Err(AuthError::Rejected);
    }

    if !config.max_time_diff.is_zero() {
        let stamp = u32::from_be_bytes(plain[4..8].try_into().unwrap());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let remote = u64::from(stamp);
        let delta = now.abs_diff(remote);

        if delta > config.max_time_diff.as_secs() {
            return Err(AuthError::Rejected);
        }
    }

    let auth_key = reality_auth_key(&x25519_shared(&config.private_key, &peer), &view.random);

    Ok(AuthenticatedHello {
        hello: view,
        auth_key,
    })
}

#[derive(Clone, Debug)]
pub struct AuthenticatedHello {
    pub hello: ClientHelloView,
    pub auth_key: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    NotClientHello,
    Rejected,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ClientTlsConfig;
    use crate::reality::auth::session_id_plain;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn test_keys() -> ([u8; 32], [u8; 32], [u8; 8]) {
        let pair = generate_keypair();
        let short = parse_short_id("aabbccdd").unwrap();
        (pair.private, pair.public, short)
    }

    #[test]
    fn session_id_roundtrip() {
        let (private, public, short) = test_keys();
        let client = generate_keypair();
        let mut random = [0u8; 32];
        random[0] = 7;
        random[20] = 9;

        let mut handshake = vec![0u8; 80];
        handshake[0] = 0x01;
        handshake[6..38].copy_from_slice(&random);
        handshake[38] = 32;

        let plain = session_id_plain(CLIENT_VERSION, 1_700_000_000, short);
        let sealed = seal_session_id(&client.private, &public, &random, &plain, &handshake);
        handshake[39..71].copy_from_slice(&sealed);

        let opened =
            open_session_id(&private, &client.public, &random, &sealed, &handshake).expect("open");

        assert_eq!(opened, plain);
    }

    #[test]
    fn dest_host_splits_port() {
        assert_eq!(
            dest_host("www.microsoft.com:443").unwrap(),
            "www.microsoft.com"
        );
        assert_eq!(dest_host("[::1]:443").unwrap(), "::1");
    }

    #[tokio::test]
    async fn authenticated_hello_completes_tls13() {
        let (private, public, short) = test_keys();
        let mut server_cfg =
            RealityServerConfig::new("localhost:443".into(), private, vec![short]).unwrap();
        // Fetching dest must fail fast so this test stays offline.
        server_cfg.dest = "127.0.0.1:1".into();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let RealityAccept::Vpn {
                stream: prefixed,
                auth_key,
                server_name,
                dest_flight,
            } = accept(tcp, &server_cfg).await.unwrap()
            else {
                panic!("expected vpn accept");
            };
            assert!(dest_flight.is_none());

            let mut tls =
                Tls13Stream::accept(prefixed, &auth_key, &server_name, dest_flight.as_ref())
                    .await
                    .unwrap();
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            tls.write_all(b"pong").await.unwrap();
        });

        let mut pin = ClientTlsConfig::default();
        pin.server_name = "localhost".into();

        let mut client = Tls13Client::connect(
            addr,
            &RealityClientConfig {
                public_key: public,
                short_id: short,
                server_name: "localhost".into(),
            },
            &pin,
        )
        .await
        .unwrap();

        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn probe_is_spliced_to_dest() {
        let dest = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dest_addr = dest.local_addr().unwrap();

        let dest_task = tokio::spawn(async move {
            let (mut tcp, _) = dest.accept().await.unwrap();
            let mut buf = [0u8; 5];
            tcp.read_exact(&mut buf).await.unwrap();
            tcp.write_all(b"dest-ok").await.unwrap();
        });

        let (private, _, short) = test_keys();
        let server_cfg =
            RealityServerConfig::new(dest_addr.to_string(), private, vec![short]).unwrap();
        // Accept any SNI so a junk hello still reaches dest after auth fail.
        let mut server_cfg = server_cfg;
        server_cfg.server_names.clear();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let outcome = accept(tcp, &server_cfg).await.unwrap();
            assert!(matches!(outcome, RealityAccept::Spliced));
        });

        let mut probe = TcpStream::connect(addr).await.unwrap();
        probe
            .write_all(&[0x16, 0x03, 0x01, 0x00, 0x01, 0x00])
            .await
            .unwrap();
        let mut buf = [0u8; 7];
        probe.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"dest-ok");

        server.await.unwrap();
        dest_task.await.unwrap();
    }

    #[tokio::test]
    async fn our_name_stays_local_instead_of_splice() {
        let dest = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dest_addr = dest.local_addr().unwrap();

        let dest_task = tokio::spawn(async move {
            let _ = dest.accept().await;
            panic!("dest should not see a local-name ClientHello");
        });

        let (private, _, short) = test_keys();
        let mut server_cfg =
            RealityServerConfig::new(dest_addr.to_string(), private, vec![short]).unwrap();
        server_cfg.server_names.clear();
        server_cfg.local_names = vec!["vpn.example.com".into()];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let outcome = accept(tcp, &server_cfg).await.unwrap();
            assert!(matches!(outcome, RealityAccept::Local { acme: false, .. }));
        });

        let hello =
            hello::build_client_hello_record(&[9u8; 32], &[8u8; 32], "vpn.example.com", &[7u8; 32]);
        let mut probe = TcpStream::connect(addr).await.unwrap();
        probe.write_all(&hello).await.unwrap();
        probe.shutdown().await.unwrap();

        server.await.unwrap();
        dest_task.abort();
    }

    #[tokio::test]
    async fn authenticated_hello_matches_dest_ja3s() {
        let dest = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dest_addr = dest.local_addr().unwrap();

        let dest_task = tokio::spawn(async move {
            let (mut tcp, _) = dest.accept().await.unwrap();
            let mut header = [0u8; 5];
            tcp.read_exact(&mut header).await.unwrap();
            let len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let mut body = vec![0u8; len];
            tcp.read_exact(&mut body).await.unwrap();

            let sh = hello::build_server_hello_handshake(
                &[3u8; 32],
                &[4u8; 32],
                0x1302,
                &[0x11u8; 32],
                &[51, 43],
            );
            let mut record = vec![0x16, 0x03, 0x03];
            record.extend_from_slice(&(sh.len() as u16).to_be_bytes());
            record.extend_from_slice(&sh);
            tcp.write_all(&record).await.unwrap();
        });

        let (private, public, short) = test_keys();
        let mut server_cfg =
            RealityServerConfig::new("localhost:443".into(), private, vec![short]).unwrap();
        server_cfg.dest = dest_addr.to_string();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let RealityAccept::Vpn {
                stream: prefixed,
                auth_key,
                server_name,
                dest_flight,
            } = accept(tcp, &server_cfg).await.unwrap()
            else {
                panic!("expected vpn accept");
            };

            let dest_flight = dest_flight.expect("dest ServerHello");
            let view = ServerHelloView::parse(&dest_flight.server_hello).unwrap();
            assert_eq!(view.ja3s(), (0x0303, 0x1302, vec![51, 43]));
            assert!(dest_flight.handshake_pad().is_none());

            let mut tls =
                Tls13Stream::accept(prefixed, &auth_key, &server_name, Some(&dest_flight))
                    .await
                    .unwrap();
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            tls.write_all(b"pong").await.unwrap();
        });

        let mut pin = ClientTlsConfig::default();
        pin.server_name = "localhost".into();

        let mut client = Tls13Client::connect(
            addr,
            &RealityClientConfig {
                public_key: public,
                short_id: short,
                server_name: "localhost".into(),
            },
            &pin,
        )
        .await
        .unwrap();

        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        server.await.unwrap();
        dest_task.await.unwrap();
    }

    fn fake_tls_record(typ: u8, total_len: usize) -> Vec<u8> {
        assert!(total_len >= 5);
        let body = total_len - 5;
        let mut record = vec![typ, 0x03, 0x03, (body >> 8) as u8, body as u8];
        record.resize(total_len, 0);
        record
    }

    #[test]
    fn dest_flight_pad_rules() {
        let combined = DestFlight {
            encrypted_record_lens: vec![1200, 180],
            ..DestFlight::default()
        };
        assert_eq!(combined.handshake_pad(), Some(1200));
        assert!(combined.split_pads().is_none());
        assert_eq!(combined.extra_pads(), &[180]);

        let split = DestFlight {
            encrypted_record_lens: vec![51, 800, 120],
            ..DestFlight::default()
        };
        assert!(split.handshake_pad().is_none());
        assert_eq!(
            split.split_pads(),
            Some([Some(51), Some(800), Some(120), None])
        );
        assert!(split.extra_pads().is_empty());

        let split_nst = DestFlight {
            encrypted_record_lens: vec![51, 800, 120, 60, 180],
            ..DestFlight::default()
        };
        assert_eq!(
            split_nst.split_pads(),
            Some([Some(51), Some(800), Some(120), Some(60)])
        );
        assert_eq!(split_nst.extra_pads(), &[180]);
    }

    #[tokio::test]
    async fn authenticated_hello_pads_dest_encrypted_tail() {
        let dest = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dest_addr = dest.local_addr().unwrap();

        let dest_task = tokio::spawn(async move {
            let (mut tcp, _) = dest.accept().await.unwrap();
            let mut header = [0u8; 5];
            tcp.read_exact(&mut header).await.unwrap();
            let len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let mut body = vec![0u8; len];
            tcp.read_exact(&mut body).await.unwrap();

            let sh = hello::build_server_hello_handshake(
                &[3u8; 32],
                &[4u8; 32],
                0x1301,
                &[0x11u8; 32],
                &[43, 51],
            );
            let mut record = vec![0x16, 0x03, 0x03];
            record.extend_from_slice(&(sh.len() as u16).to_be_bytes());
            record.extend_from_slice(&sh);
            tcp.write_all(&record).await.unwrap();
            tcp.write_all(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01])
                .await
                .unwrap();
            tcp.write_all(&fake_tls_record(0x17, 1200)).await.unwrap();
            tcp.write_all(&fake_tls_record(0x17, 180)).await.unwrap();
            tcp.flush().await.unwrap();
            let _ = tcp.read(&mut [0u8; 1]).await;
        });

        let (private, public, short) = test_keys();
        let mut server_cfg =
            RealityServerConfig::new("localhost:443".into(), private, vec![short]).unwrap();
        server_cfg.dest = dest_addr.to_string();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let RealityAccept::Vpn {
                stream: prefixed,
                auth_key,
                server_name,
                dest_flight,
            } = accept(tcp, &server_cfg).await.unwrap()
            else {
                panic!("expected vpn accept");
            };

            let dest_flight = dest_flight.expect("dest flight");
            assert_eq!(dest_flight.handshake_pad(), Some(1200));
            assert_eq!(dest_flight.extra_pads(), &[180]);

            let mut tls =
                Tls13Stream::accept(prefixed, &auth_key, &server_name, Some(&dest_flight))
                    .await
                    .unwrap();
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            tls.write_all(b"pong").await.unwrap();
        });

        let mut pin = ClientTlsConfig::default();
        pin.server_name = "localhost".into();

        let mut client = Tls13Client::connect(
            addr,
            &RealityClientConfig {
                public_key: public,
                short_id: short,
                server_name: "localhost".into(),
            },
            &pin,
        )
        .await
        .unwrap();

        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        server.await.unwrap();
        dest_task.await.unwrap();
    }

    #[tokio::test]
    async fn authenticated_hello_splits_dest_encrypted_tail() {
        let dest = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dest_addr = dest.local_addr().unwrap();

        let dest_task = tokio::spawn(async move {
            let (mut tcp, _) = dest.accept().await.unwrap();
            let mut header = [0u8; 5];
            tcp.read_exact(&mut header).await.unwrap();
            let len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let mut body = vec![0u8; len];
            tcp.read_exact(&mut body).await.unwrap();

            let sh = hello::build_server_hello_handshake(
                &[3u8; 32],
                &[4u8; 32],
                0x1301,
                &[0x11u8; 32],
                &[43, 51],
            );
            let mut record = vec![0x16, 0x03, 0x03];
            record.extend_from_slice(&(sh.len() as u16).to_be_bytes());
            record.extend_from_slice(&sh);
            tcp.write_all(&record).await.unwrap();
            tcp.write_all(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01])
                .await
                .unwrap();
            for len in [80usize, 900, 200, 100, 180] {
                tcp.write_all(&fake_tls_record(0x17, len)).await.unwrap();
            }
            tcp.flush().await.unwrap();
            let _ = tcp.read(&mut [0u8; 1]).await;
        });

        let (private, public, short) = test_keys();
        let mut server_cfg =
            RealityServerConfig::new("localhost:443".into(), private, vec![short]).unwrap();
        server_cfg.dest = dest_addr.to_string();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let RealityAccept::Vpn {
                stream: prefixed,
                auth_key,
                server_name,
                dest_flight,
            } = accept(tcp, &server_cfg).await.unwrap()
            else {
                panic!("expected vpn accept");
            };

            let dest_flight = dest_flight.expect("dest flight");
            assert!(dest_flight.handshake_pad().is_none());
            assert_eq!(
                dest_flight.split_pads(),
                Some([Some(80), Some(900), Some(200), Some(100)])
            );
            assert_eq!(dest_flight.extra_pads(), &[180]);

            let mut tls =
                Tls13Stream::accept(prefixed, &auth_key, &server_name, Some(&dest_flight))
                    .await
                    .unwrap();
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            tls.write_all(b"pong").await.unwrap();
        });

        let mut pin = ClientTlsConfig::default();
        pin.server_name = "localhost".into();

        let mut client = Tls13Client::connect(
            addr,
            &RealityClientConfig {
                public_key: public,
                short_id: short,
                server_name: "localhost".into(),
            },
            &pin,
        )
        .await
        .unwrap();

        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        server.await.unwrap();
        dest_task.await.unwrap();
    }

    #[tokio::test]
    async fn authenticated_hello_skips_post_handshake_dummies() {
        let dest = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dest_addr = dest.local_addr().unwrap();

        let dest_task = tokio::spawn(async move {
            let (mut tcp, _) = dest.accept().await.unwrap();
            let mut header = [0u8; 5];
            tcp.read_exact(&mut header).await.unwrap();
            let len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let mut body = vec![0u8; len];
            tcp.read_exact(&mut body).await.unwrap();

            let sh = hello::build_server_hello_handshake(
                &[3u8; 32],
                &[4u8; 32],
                0x1301,
                &[0x11u8; 32],
                &[43, 51],
            );
            let mut record = vec![0x16, 0x03, 0x03];
            record.extend_from_slice(&(sh.len() as u16).to_be_bytes());
            record.extend_from_slice(&sh);
            tcp.write_all(&record).await.unwrap();
            let _ = tcp.read(&mut [0u8; 1]).await;
        });

        let (private, public, short) = test_keys();
        let mut server_cfg =
            RealityServerConfig::new("localhost:443".into(), private, vec![short]).unwrap();
        server_cfg.dest = dest_addr.to_string();
        server_cfg.post_handshake.lock().unwrap()[2] = vec![140, 90];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let RealityAccept::Vpn {
                stream: prefixed,
                auth_key,
                server_name,
                dest_flight,
            } = accept(tcp, &server_cfg).await.unwrap()
            else {
                panic!("expected vpn accept");
            };

            let dest_flight = dest_flight.expect("dest flight");
            assert_eq!(dest_flight.post_handshake_pads(), &[140, 90]);

            let mut tls =
                Tls13Stream::accept(prefixed, &auth_key, &server_name, Some(&dest_flight))
                    .await
                    .unwrap();
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            tls.write_all(b"pong").await.unwrap();
        });

        let mut pin = ClientTlsConfig::default();
        pin.server_name = "localhost".into();

        let mut client = Tls13Client::connect(
            addr,
            &RealityClientConfig {
                public_key: public,
                short_id: short,
                server_name: "localhost".into(),
            },
            &pin,
        )
        .await
        .unwrap();

        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        server.await.unwrap();
        dest_task.await.unwrap();
    }
}
