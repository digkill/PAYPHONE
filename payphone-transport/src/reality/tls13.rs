use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
    time::{SystemTime, UNIX_EPOCH},
};

use rand_core::{OsRng, TryRngCore};
use rustls::pki_types::CertificateDer;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
};
use webpki::EndEntityCert;

use crate::identity::{ClientTlsConfig, load_certificates};

use super::{
    CLIENT_VERSION, DestFlight, RealityClientConfig,
    auth::{
        ct_eq, reality_auth_key, seal_session_id, session_id_plain, x25519_public, x25519_shared,
    },
    cert::{mint_hmac_leaf, sign_hmac_leaf, verify_hmac_certificate},
    hello::{
        ClientHelloView, SESSION_ID_OFFSET, ServerHelloView, build_client_hello_handshake,
        build_server_hello_handshake, patch_server_hello_x25519,
    },
    suite::{
        Suite, TLS_AES_128_GCM_SHA256, TrafficKeys, Transcript, application_traffic_keys,
        decrypt_app, encrypt_app, finished_verify, handshake_traffic_keys,
    },
};

const MAX_RECORD: usize = 16 * 1024 + 256;

pub struct Tls13Stream<S> {
    inner: S,
    send: TrafficKeys,
    recv: TrafficKeys,
    assembler: RecordAssembler,
    plaintext: Vec<u8>,
    plaintext_at: usize,
    pending: Vec<u8>,
    pending_at: usize,
    pending_plain: usize,
}

pub type Tls13Client = Tls13Stream<TcpStream>;

struct RecordAssembler {
    header: [u8; 5],
    header_got: usize,
    body: Vec<u8>,
    body_got: usize,
}

impl Default for RecordAssembler {
    fn default() -> Self {
        Self {
            header: [0; 5],
            header_got: 0,
            body: Vec::new(),
            body_got: 0,
        }
    }
}

impl Tls13Stream<TcpStream> {
    pub async fn connect(
        address: std::net::SocketAddr,
        reality: &RealityClientConfig,
        tls: &ClientTlsConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let pin = load_pin(tls).ok();
        let mut client_private = [0u8; 32];
        OsRng.try_fill_bytes(&mut client_private)?;
        let client_public = x25519_public(&client_private);

        let mut random = [0u8; 32];
        OsRng.try_fill_bytes(&mut random)?;

        let unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        let plain = session_id_plain(CLIENT_VERSION, unix, reality.short_id);
        let zeros = [0u8; 32];
        let mut handshake =
            build_client_hello_handshake(&random, &zeros, &reality.server_name, &client_public);
        let sealed = seal_session_id(
            &client_private,
            &reality.public_key,
            &random,
            &plain,
            &handshake,
        );
        handshake[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32].copy_from_slice(&sealed);

        let auth_key = reality_auth_key(
            &x25519_shared(&client_private, &reality.public_key),
            &random,
        );

        let mut record = Vec::with_capacity(5 + handshake.len());
        record.push(0x16);
        record.extend_from_slice(&0x0301u16.to_be_bytes());
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        let mut tcp = TcpStream::connect(address).await?;
        tcp.set_nodelay(true)?;
        tcp.write_all(&record).await?;
        tcp.flush().await?;

        let server_hello_msg = read_server_hello_msg(&mut tcp).await?;
        let view = ServerHelloView::parse(&server_hello_msg).ok_or("bad ServerHello")?;
        let suite = Suite::from_id(view.cipher).ok_or("unsupported ServerHello cipher")?;
        let peer_public = view
            .x25519_public
            .ok_or("ServerHello missing X25519 key_share")?;

        let mut transcript = Transcript::new(suite);
        transcript.update(&handshake);
        transcript.update(&server_hello_msg);

        let shared = x25519_shared(&client_private, &peer_public);
        let (mut client_hs, mut server_hs, handshake_secret) =
            handshake_traffic_keys(suite, &shared, &transcript.hash());

        let mut hs_buf = Vec::new();
        let mut server_finished = None;
        let mut leaf_der: Option<Vec<u8>> = None;

        while server_finished.is_none() {
            let (typ, body) = read_record(&mut tcp).await?;

            match typ {
                0x14 => continue,
                0x17 => {
                    let (inner, content) = server_hs.keys.decrypt(&body)?;

                    if inner != 0x16 {
                        return Err("unexpected inner type during handshake".into());
                    }

                    hs_buf.extend_from_slice(&content);

                    while let Some((msg, rest)) = split_handshake(&hs_buf) {
                        hs_buf = rest;
                        match msg[0] {
                            8 => transcript.update(&msg),
                            11 => {
                                let leaf = parse_certificate(&msg)?;
                                let hmac_ok = verify_hmac_certificate(&auth_key, &leaf);
                                let pin_ok = pin.as_ref().is_some_and(|pin| pin == &leaf);

                                if !hmac_ok && !pin_ok {
                                    return Err("REALITY TLS cert HMAC mismatch".into());
                                }

                                leaf_der = Some(leaf);
                                transcript.update(&msg);
                            }
                            15 => {
                                let leaf = leaf_der
                                    .as_ref()
                                    .ok_or("CertificateVerify before Certificate")?;
                                verify_certificate_verify(leaf, &msg, &transcript.hash())?;
                                transcript.update(&msg);
                            }
                            20 => {
                                let hash_len = suite.hash_len();
                                if msg.len() < 4 + hash_len {
                                    return Err("short server Finished".into());
                                }

                                let expected =
                                    finished_verify(suite, &server_hs.secret, &transcript.hash());
                                if !ct_eq(&msg[4..], &expected) {
                                    return Err("server Finished mismatch".into());
                                }
                                transcript.update(&msg);
                                server_finished = Some(());
                            }
                            4 | 24 => {
                                if server_finished.is_none() {
                                    return Err(
                                        format!("unexpected handshake type {}", msg[0]).into()
                                    );
                                }
                            }
                            other => {
                                return Err(format!("unexpected handshake type {other}").into());
                            }
                        }
                    }
                }
                other => {
                    return Err(format!("unexpected TLS record {other} during handshake").into());
                }
            }
        }

        let (client_app, server_app) =
            application_traffic_keys(suite, &handshake_secret, &transcript.hash());

        let verify = finished_verify(suite, &client_hs.secret, &transcript.hash());
        let finished = handshake_msg(20, &verify);

        tcp.write_all(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]).await?;
        let encrypted = client_hs.keys.encrypt(0x16, &finished);
        tcp.write_all(&encrypted).await?;
        tcp.flush().await?;

        Ok(Self {
            inner: tcp,
            send: client_app,
            recv: server_app,
            assembler: RecordAssembler::default(),
            plaintext: Vec::new(),
            plaintext_at: 0,
            pending: Vec::new(),
            pending_at: 0,
            pending_plain: 0,
        })
    }
}

impl<S> Tls13Stream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn accept(
        mut inner: S,
        auth_key: &[u8; 32],
        server_name: &str,
        dest_flight: Option<&DestFlight>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (typ, body) = read_record(&mut inner)
            .await
            .map_err(|error| -> Box<dyn std::error::Error + Send + Sync> { error.into() })?;

        if typ != 0x16 {
            return Err("expected ClientHello record".into());
        }

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(body.len() as u16).to_be_bytes());
        record.extend_from_slice(&body);
        let view = ClientHelloView::parse(&record).ok_or("bad ClientHello")?;
        let client_public = view.x25519_public.ok_or("ClientHello missing X25519")?;
        let (hello_msg, rest) = split_handshake(&body).ok_or("truncated ClientHello")?;

        if hello_msg[0] != 1 || !rest.is_empty() {
            return Err("expected a single ClientHello".into());
        }

        let mut server_private = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut server_private)
            .map_err(|error| error.to_string())?;
        let server_public = x25519_public(&server_private);

        let dest_hello = dest_flight.map(|flight| flight.server_hello.as_slice());
        let server_hello = match dest_server_hello(dest_hello, &server_public) {
            Some(hello) => hello,
            None => {
                let mut server_random = [0u8; 32];
                OsRng
                    .try_fill_bytes(&mut server_random)
                    .map_err(|error| error.to_string())?;
                build_server_hello_handshake(
                    &server_random,
                    &view.session_id,
                    TLS_AES_128_GCM_SHA256,
                    &server_public,
                    &[43, 51],
                )
            }
        };

        let sh_view = ServerHelloView::parse(&server_hello).ok_or("bad ServerHello")?;
        let suite = Suite::from_id(sh_view.cipher).ok_or("unsupported dest cipher")?;
        let mut transcript = Transcript::new(suite);
        transcript.update(&hello_msg);
        transcript.update(&server_hello);

        inner
            .write_all(&tls_record(0x16, &server_hello))
            .await
            .map_err(io_err)?;
        inner
            .write_all(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01])
            .await
            .map_err(io_err)?;

        let shared = x25519_shared(&server_private, &client_public);
        let (mut client_hs, mut server_hs, handshake_secret) =
            handshake_traffic_keys(suite, &shared, &transcript.hash());

        let (leaf, key_pair) = mint_hmac_leaf(auth_key, server_name)?;
        let ee = encrypted_extensions_msg(&view.alpn);
        transcript.update(&ee);
        let cert = certificate_msg(&leaf);
        transcript.update(&cert);
        let cv = certificate_verify_msg(&key_pair, &transcript.hash())?;
        transcript.update(&cv);
        let fin = handshake_msg(
            20,
            &finished_verify(suite, &server_hs.secret, &transcript.hash()),
        );
        transcript.update(&fin);

        if let Some(pads) = dest_flight.and_then(DestFlight::split_pads) {
            for (msg, pad) in [&ee, &cert, &cv, &fin].into_iter().zip(pads) {
                let encrypted = server_hs.keys.encrypt_padded(0x16, msg, pad);
                inner.write_all(&encrypted).await.map_err(io_err)?;
            }
        } else {
            let mut flight = Vec::new();
            flight.extend_from_slice(&ee);
            flight.extend_from_slice(&cert);
            flight.extend_from_slice(&cv);
            flight.extend_from_slice(&fin);
            let pad = dest_flight.and_then(DestFlight::handshake_pad);
            let encrypted = server_hs.keys.encrypt_padded(0x16, &flight, pad);
            inner.write_all(&encrypted).await.map_err(io_err)?;
        }

        let (client_app, mut server_app) =
            application_traffic_keys(suite, &handshake_secret, &transcript.hash());

        if let Some(dest) = dest_flight {
            for extra in dest.extra_pads() {
                // header + NST type + inner content type + GCM tag
                if *extra < 5 + 1 + 1 + 16 {
                    continue;
                }
                let dummy = server_app.encrypt_padded(0x16, &[4], Some(*extra));
                inner.write_all(&dummy).await.map_err(io_err)?;
            }
        }

        inner.flush().await.map_err(io_err)?;

        loop {
            let (typ, body) = read_record(&mut inner).await.map_err(io_err)?;

            match typ {
                0x14 => continue,
                0x17 => {
                    let (inner_typ, content) = client_hs.keys.decrypt(&body).map_err(io_err)?;

                    if inner_typ != 0x16 {
                        return Err("expected client handshake Finished".into());
                    }

                    let (msg, _) = split_handshake(&content).ok_or("truncated client Finished")?;
                    let hash_len = suite.hash_len();

                    if msg[0] != 20 || msg.len() < 4 + hash_len {
                        return Err("expected client Finished".into());
                    }

                    let expected = finished_verify(suite, &client_hs.secret, &transcript.hash());

                    if !ct_eq(&msg[4..], &expected) {
                        return Err("client Finished mismatch".into());
                    }

                    break;
                }
                other => {
                    return Err(format!("unexpected TLS record {other} after ServerHello").into());
                }
            }
        }

        if let Some(dest) = dest_flight {
            for extra in dest.post_handshake_pads() {
                if *extra < 5 + 1 + 1 + 16 {
                    continue;
                }
                let dummy = server_app.encrypt_padded(0x16, &[4], Some(*extra));
                inner.write_all(&dummy).await.map_err(io_err)?;
            }
            inner.flush().await.map_err(io_err)?;
        }

        Ok(Self {
            inner,
            send: server_app,
            recv: client_app,
            assembler: RecordAssembler::default(),
            plaintext: Vec::new(),
            plaintext_at: 0,
            pending: Vec::new(),
            pending_at: 0,
            pending_plain: 0,
        })
    }
}

fn dest_server_hello(dest_hello: Option<&[u8]>, server_public: &[u8; 32]) -> Option<Vec<u8>> {
    let raw = dest_hello?;
    let mut patched = raw.to_vec();
    let view = ServerHelloView::parse(&patched)?;
    Suite::from_id(view.cipher)?;
    if !patch_server_hello_x25519(&mut patched, server_public) {
        return None;
    }
    Some(patched)
}

fn io_err(error: io::Error) -> Box<dyn std::error::Error + Send + Sync> {
    error.into()
}

async fn read_record<S: AsyncRead + Unpin>(tcp: &mut S) -> io::Result<(u8, Vec<u8>)> {
    let mut header = [0u8; 5];
    tcp.read_exact(&mut header).await?;
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;

    if len == 0 || len > MAX_RECORD {
        return Err(io::Error::other("invalid tls record length"));
    }

    let mut body = vec![0u8; len];
    tcp.read_exact(&mut body).await?;
    Ok((header[0], body))
}

fn tls_record(typ: u8, body: &[u8]) -> Vec<u8> {
    let mut record = vec![typ, 0x03, 0x03];
    record.extend_from_slice(&(body.len() as u16).to_be_bytes());
    record.extend_from_slice(body);
    record
}

fn handshake_msg(typ: u8, body: &[u8]) -> Vec<u8> {
    let mut msg = vec![typ];
    msg.extend_from_slice(&u24_bytes(body.len()));
    msg.extend_from_slice(body);
    msg
}

fn tls_ext(typ: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&typ.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// Dest EncryptedExtensions plaintext is inside AEAD; we cannot copy it.
/// Echo the client's ALPN (h2 if offered) so the handshake is valid TLS 1.3.
/// Record *sizes* still come from dest (see `DestFlight`).
fn encrypted_extensions_msg(alpn: &[Vec<u8>]) -> Vec<u8> {
    let proto = if alpn.iter().any(|item| item.as_slice() == b"h2") {
        Some(&b"h2"[..])
    } else {
        alpn.first().map(Vec::as_slice)
    };

    let Some(proto) = proto else {
        return handshake_msg(8, &[0, 0]);
    };

    let mut alpn_payload = Vec::new();
    alpn_payload.extend_from_slice(&((1 + proto.len()) as u16).to_be_bytes());
    alpn_payload.push(proto.len() as u8);
    alpn_payload.extend_from_slice(proto);
    let alpn_ext = tls_ext(16, &alpn_payload);
    let mut body = Vec::new();
    body.extend_from_slice(&(alpn_ext.len() as u16).to_be_bytes());
    body.extend(alpn_ext);
    handshake_msg(8, &body)
}

fn certificate_msg(der: &[u8]) -> Vec<u8> {
    let mut entry = Vec::new();
    entry.extend_from_slice(&u24_bytes(der.len()));
    entry.extend_from_slice(der);
    entry.extend_from_slice(&0u16.to_be_bytes());
    let mut body = vec![0u8];
    body.extend_from_slice(&u24_bytes(entry.len()));
    body.extend_from_slice(&entry);
    handshake_msg(11, &body)
}

fn certificate_verify_msg(
    key_pair: &rcgen::KeyPair,
    transcript_hash: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut signed = vec![0x20u8; 64];
    signed.extend_from_slice(b"TLS 1.3, server CertificateVerify\x00");
    signed.extend_from_slice(transcript_hash);
    let signature = sign_hmac_leaf(key_pair, &signed)?;
    let mut body = Vec::new();
    body.extend_from_slice(&0x0807u16.to_be_bytes());
    body.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    body.extend_from_slice(&signature);
    Ok(handshake_msg(15, &body))
}

fn u24_bytes(len: usize) -> [u8; 3] {
    [(len >> 16) as u8, (len >> 8) as u8, len as u8]
}

async fn read_server_hello_msg<S: AsyncRead + Unpin>(
    tcp: &mut S,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut leftover = Vec::new();

    loop {
        let (typ, body) = read_record(tcp).await?;

        if typ != 0x16 {
            return Err("expected handshake record for ServerHello".into());
        }

        leftover.extend_from_slice(&body);

        if let Some((msg, _rest)) = split_handshake(&leftover) {
            if msg[0] != 2 {
                return Err("expected ServerHello".into());
            }

            return Ok(msg);
        }
    }
}

fn parse_certificate(msg: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let body_len = u24(&msg[1..4]).ok_or("bad Certificate length")?;
    let body = msg.get(4..4 + body_len).ok_or("truncated Certificate")?;
    let mut i = 1;
    let list_len = u24(body.get(i..i + 3).ok_or("no cert list")?).ok_or("bad cert list")?;
    i += 3;
    let list = body.get(i..i + list_len).ok_or("truncated cert list")?;
    let cert_len = u24(list.get(..3).ok_or("no leaf length")?).ok_or("bad leaf length")?;
    Ok(list.get(3..3 + cert_len).ok_or("truncated leaf")?.to_vec())
}

fn verify_certificate_verify(
    leaf: &[u8],
    msg: &[u8],
    transcript_hash: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let body_len = u24(&msg[1..4]).ok_or("bad CertificateVerify length")?;
    let body = msg
        .get(4..4 + body_len)
        .ok_or("truncated CertificateVerify")?;
    let scheme = u16::from_be_bytes(body.get(..2).ok_or("no scheme")?.try_into().unwrap());
    let sig_len =
        u16::from_be_bytes(body.get(2..4).ok_or("no sig len")?.try_into().unwrap()) as usize;
    let signature = body.get(4..4 + sig_len).ok_or("truncated signature")?;

    let mut signed = vec![0x20u8; 64];
    signed.extend_from_slice(b"TLS 1.3, server CertificateVerify\x00");
    signed.extend_from_slice(transcript_hash);

    let der = CertificateDer::from(leaf.to_vec());
    let cert = EndEntityCert::try_from(&der).map_err(|error| error.to_string())?;
    let result = match scheme {
        0x0403 => cert.verify_signature(webpki::ring::ECDSA_P256_SHA256, &signed, signature),
        0x0503 => cert.verify_signature(webpki::ring::ECDSA_P384_SHA384, &signed, signature),
        0x0804 => cert.verify_signature(
            webpki::ring::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
            &signed,
            signature,
        ),
        0x0805 => cert.verify_signature(
            webpki::ring::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
            &signed,
            signature,
        ),
        0x0807 => cert.verify_signature(webpki::ring::ED25519, &signed, signature),
        other => return Err(format!("unsupported CertificateVerify scheme {other:#06x}").into()),
    };

    result.map_err(|error| format!("CertificateVerify: {error}").into())
}

fn load_pin(tls: &ClientTlsConfig) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let certs = load_certificates(&tls.pin_path)?;
    Ok(certs[0].as_ref().to_vec())
}

fn split_handshake(buf: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    if buf.len() < 4 {
        return None;
    }

    let len = u24(&buf[1..4])?;

    if buf.len() < 4 + len {
        return None;
    }

    Some((buf[..4 + len].to_vec(), buf[4 + len..].to_vec()))
}

fn u24(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 3 {
        return None;
    }

    Some(((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize)
}

impl RecordAssembler {
    fn poll_record<S: AsyncRead + Unpin>(
        &mut self,
        tcp: &mut S,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<(u8, Vec<u8>)>> {
        while self.header_got < 5 {
            let mut buf = ReadBuf::new(&mut self.header[self.header_got..]);
            ready!(Pin::new(&mut *tcp).poll_read(cx, &mut buf))?;
            let n = buf.filled().len();

            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }

            self.header_got += n;
        }

        if self.body.is_empty() && self.body_got == 0 {
            let len = u16::from_be_bytes([self.header[3], self.header[4]]) as usize;

            if len == 0 || len > MAX_RECORD {
                return Poll::Ready(Err(io::Error::other("invalid tls record length")));
            }

            self.body.resize(len, 0);
        }

        while self.body_got < self.body.len() {
            let mut buf = ReadBuf::new(&mut self.body[self.body_got..]);
            ready!(Pin::new(&mut *tcp).poll_read(cx, &mut buf))?;
            let n = buf.filled().len();

            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }

            self.body_got += n;
        }

        let typ = self.header[0];
        let body = std::mem::take(&mut self.body);
        self.header_got = 0;
        self.body_got = 0;
        Poll::Ready(Ok((typ, body)))
    }
}

impl<S: AsyncRead + Unpin> Tls13Stream<S> {
    fn poll_fill_plaintext(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.plaintext_at < self.plaintext.len() {
            return Poll::Ready(Ok(()));
        }

        self.plaintext.clear();
        self.plaintext_at = 0;

        loop {
            let this = self.as_mut().get_mut();
            let (typ, body) = ready!(this.assembler.poll_record(&mut this.inner, cx))?;

            match typ {
                0x17 => {
                    let (inner, content) = decrypt_app(&this.recv, &body)?;
                    this.recv.seq += 1;

                    match inner {
                        0x17 => {
                            this.plaintext = content;
                            return Poll::Ready(Ok(()));
                        }
                        0x16 => continue,
                        0x15 => {
                            return Poll::Ready(Err(io::Error::other("tls alert")));
                        }
                        other => {
                            return Poll::Ready(Err(io::Error::other(format!(
                                "unexpected tls inner type {other}"
                            ))));
                        }
                    }
                }
                0x15 => return Poll::Ready(Err(io::Error::other("tls alert"))),
                0x14 => continue,
                other => {
                    return Poll::Ready(Err(io::Error::other(format!(
                        "unexpected tls record {other}"
                    ))));
                }
            }
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Tls13Stream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_fill_plaintext(cx))?;

        let this = self.get_mut();
        let available = this.plaintext.len() - this.plaintext_at;
        let take = available.min(buf.remaining());
        buf.put_slice(&this.plaintext[this.plaintext_at..this.plaintext_at + take]);
        this.plaintext_at += take;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Tls13Stream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let this = self.as_mut().get_mut();

            if !this.pending.is_empty() {
                let n = {
                    let Tls13Stream {
                        inner,
                        pending,
                        pending_at,
                        ..
                    } = this;
                    ready!(Pin::new(inner).poll_write(cx, &pending[*pending_at..]))?
                };

                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }

                this.pending_at += n;

                if this.pending_at < this.pending.len() {
                    continue;
                }

                let reported = this.pending_plain;
                this.pending.clear();
                this.pending_at = 0;
                this.pending_plain = 0;
                return Poll::Ready(Ok(reported));
            }

            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }

            let chunk = &buf[..buf.len().min(14 * 1024)];
            this.pending = encrypt_app(&this.send, 0x17, chunk);
            this.send.seq += 1;
            this.pending_at = 0;
            this.pending_plain = chunk.len();
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let record = encrypt_app(&self.send, 0x15, &[1, 0]);
        self.send.seq += 1;
        let _ = Pin::new(&mut self.inner).poll_write(cx, &record);
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_extensions_echoes_h2() {
        let msg = encrypted_extensions_msg(&[b"h2".to_vec(), b"http/1.1".to_vec()]);
        assert_eq!(msg[0], 8);
        assert!(msg.windows(2).any(|w| w == b"h2"));
        assert!(!msg.windows(8).any(|w| w == b"http/1.1"));
    }

    #[test]
    fn encrypted_extensions_empty_without_alpn() {
        let msg = encrypted_extensions_msg(&[]);
        assert_eq!(msg, handshake_msg(8, &[0, 0]));
    }

    #[test]
    fn encrypted_extensions_echoes_http11_when_no_h2() {
        let msg = encrypted_extensions_msg(&[b"http/1.1".to_vec()]);
        assert!(msg.windows(8).any(|w| w == b"http/1.1"));
    }
}
