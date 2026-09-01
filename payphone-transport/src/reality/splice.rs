use std::{
    io::{self, Cursor},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
    time::timeout,
};

use super::hello::{ServerHelloView, handshake_from_record};
use super::{RealityServerConfig, authenticate, dest_host};

const MAX_RECORD: usize = 16 * 1024;
const PEEK_TIMEOUT: Duration = Duration::from_secs(10);
const DEST_TIMEOUT: Duration = Duration::from_secs(8);
const DEST_TAIL_WAIT: Duration = Duration::from_millis(250);

/// Dest's ServerHello plus ciphertext record sizes (JA3S + encrypted tail).
#[derive(Clone, Debug, Default)]
pub struct DestFlight {
    pub server_hello: Vec<u8>,
    pub encrypted_record_lens: Vec<usize>,
    pub post_handshake_lens: Vec<usize>,
}

impl DestFlight {
    /// Dest put EncryptedExtensions+… in one record (>512). Pad our flight to that.
    pub fn handshake_pad(&self) -> Option<usize> {
        let first = *self.encrypted_record_lens.first()?;
        (first > 512).then_some(first)
    }

    /// Dest sent separate EE/Cert/CV/Finished records. Pad each message; `None` = no pad.
    pub fn split_pads(&self) -> Option<[Option<usize>; 4]> {
        if self.handshake_pad().is_some() || self.encrypted_record_lens.is_empty() {
            return None;
        }

        let mut pads = [None; 4];
        for (i, len) in self.encrypted_record_lens.iter().take(4).enumerate() {
            pads[i] = Some(*len);
        }
        Some(pads)
    }

    /// Dest records after the handshake flight (usually NewSessionTicket).
    pub fn extra_pads(&self) -> &[usize] {
        if self.handshake_pad().is_some() {
            self.encrypted_record_lens.get(1..).unwrap_or(&[])
        } else if self.encrypted_record_lens.len() > 4 {
            &self.encrypted_record_lens[4..]
        } else {
            &[]
        }
    }

    pub fn post_handshake_pads(&self) -> &[usize] {
        &self.post_handshake_lens
    }
}

pub enum RealityAccept {
    Vpn {
        stream: PrefixedStream,
        auth_key: [u8; 32],
        server_name: String,
        dest_flight: Option<DestFlight>,
    },
    /// Our name or an ACME TLS-ALPN-01 probe. Replay the ClientHello
    /// into rustls instead of splicing to dest — so REALITY can stay
    /// on without killing the landing page / Let's Encrypt.
    Local {
        stream: PrefixedStream,
        acme: bool,
    },
    Spliced,
}

pub async fn accept(
    mut tcp: TcpStream,
    config: &RealityServerConfig,
) -> Result<RealityAccept, Box<dyn std::error::Error + Send + Sync>> {
    let record = match timeout(PEEK_TIMEOUT, read_tls_record(&mut tcp)).await {
        Ok(Ok(record)) => record,
        Ok(Err(error)) => return Err(error.into()),
        Err(_) => return Err("REALITY ClientHello timed out".into()),
    };

    if let Ok(auth) = authenticate(&record, config) {
        let alpn = auth.hello.alpn_class();
        let server_name = auth
            .hello
            .sni
            .unwrap_or_else(|| dest_host(&config.dest).unwrap_or_else(|_| "localhost".into()));
        let mut dest_flight = fetch_dest_flight(&config.dest, &record).await;
        if let Some(flight) = dest_flight.as_mut() {
            flight.post_handshake_lens = config.post_handshake_lens_for(alpn);
        } else if !config.post_handshake_lens_for(alpn).is_empty() {
            dest_flight = Some(DestFlight {
                post_handshake_lens: config.post_handshake_lens_for(alpn),
                ..DestFlight::default()
            });
        }

        return Ok(RealityAccept::Vpn {
            stream: PrefixedStream::new(record, tcp),
            auth_key: auth.auth_key,
            server_name,
            dest_flight,
        });
    }

    if local_hello(&record, config) {
        let acme = crate::reality::hello::ClientHelloView::parse(&record)
            .is_some_and(|view| view.has_acme_alpn());
        return Ok(RealityAccept::Local {
            stream: PrefixedStream::new(record, tcp),
            acme,
        });
    }

    splice(record, tcp, &config.dest).await?;

    Ok(RealityAccept::Spliced)
}

fn local_hello(record: &[u8], config: &RealityServerConfig) -> bool {
    let Some(view) = crate::reality::hello::ClientHelloView::parse(record) else {
        return false;
    };

    if view.has_acme_alpn() {
        return true;
    }

    let Some(sni) = view.sni.as_deref() else {
        return false;
    };

    config
        .local_names
        .iter()
        .any(|name| name.eq_ignore_ascii_case(sni))
}

pub async fn read_tls_record(tcp: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 5];
    tcp.read_exact(&mut header).await?;

    if header[0] != 0x16 {
        return Ok(header.to_vec());
    }

    let len = u16::from_be_bytes([header[3], header[4]]) as usize;

    if len == 0 || len > MAX_RECORD {
        return Ok(header.to_vec());
    }

    let mut record = Vec::with_capacity(5 + len);
    record.extend_from_slice(&header);
    record.resize(5 + len, 0);
    tcp.read_exact(&mut record[5..]).await?;
    Ok(record)
}

/// Full TLS record for dest copy (CCS and 0x17 too — peek-hello only reads 0x16).
async fn read_full_tls_record(tcp: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 5];
    tcp.read_exact(&mut header).await?;
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;

    if len > MAX_RECORD {
        return Err(io::Error::other("tls record too long"));
    }

    let mut record = vec![0u8; 5 + len];
    record[..5].copy_from_slice(&header);
    if len > 0 {
        tcp.read_exact(&mut record[5..]).await?;
    }
    Ok(record)
}

/// Dial dest with the client's ClientHello, take dest's ServerHello, then
/// sample encrypted record sizes (EE/Cert flight and NST).
async fn fetch_dest_flight(dest: &str, client_hello: &[u8]) -> Option<DestFlight> {
    let mut dest = timeout(DEST_TIMEOUT, TcpStream::connect(dest))
        .await
        .ok()?
        .ok()?;
    let _ = dest.set_nodelay(true);
    dest.write_all(client_hello).await.ok()?;
    dest.flush().await.ok()?;

    let record = timeout(DEST_TIMEOUT, read_full_tls_record(&mut dest))
        .await
        .ok()?
        .ok()?;
    let handshake = handshake_from_record(&record)?;
    let _ = ServerHelloView::parse(handshake)?;

    let mut encrypted_record_lens = Vec::new();
    let mut seen_encrypted = false;
    loop {
        if encrypted_record_lens.len() >= 8 {
            break;
        }

        let wait = if seen_encrypted {
            DEST_TAIL_WAIT
        } else {
            DEST_TIMEOUT
        };
        let next = match timeout(wait, read_full_tls_record(&mut dest)).await {
            Ok(Ok(record)) => record,
            _ => break,
        };

        match next.first().copied() {
            Some(0x14) => continue,
            Some(0x17) => {
                seen_encrypted = true;
                encrypted_record_lens.push(next.len());
            }
            _ => break,
        }
    }

    Some(DestFlight {
        server_hello: handshake.to_vec(),
        encrypted_record_lens,
        post_handshake_lens: Vec::new(),
    })
}

async fn splice(prefix: Vec<u8>, mut client: TcpStream, dest: &str) -> io::Result<()> {
    let mut dest = timeout(DEST_TIMEOUT, TcpStream::connect(dest))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "REALITY dest connect timed out"))?
        .map_err(|error| io::Error::other(format!("REALITY dest {dest}: {error}")))?;

    dest.set_nodelay(true)?;
    dest.write_all(&prefix).await?;
    dest.flush().await?;
    let _ = tokio::io::copy_bidirectional(&mut client, &mut dest).await;
    Ok(())
}

pub struct PrefixedStream {
    prefix: Option<Cursor<Vec<u8>>>,
    inner: TcpStream,
}

impl PrefixedStream {
    pub fn new(prefix: Vec<u8>, inner: TcpStream) -> Self {
        Self {
            prefix: Some(Cursor::new(prefix)),
            inner,
        }
    }
}

impl AsyncRead for PrefixedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(prefix) = self.prefix.as_mut() {
            let before = buf.filled().len();

            match Pin::new(prefix).poll_read(cx, buf) {
                Poll::Ready(Ok(())) if buf.filled().len() == before => {
                    self.prefix = None;
                }
                other => return other,
            }
        }

        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
