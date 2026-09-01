//! Dest post-handshake record sizes (Xray `GlobalPostHandshakeRecordsLens`).
//!
//! After a real TLS 1.3 handshake with dest, leftover `0x17` records (second
//! NewSessionTicket, etc.) are measured. Authenticated PAYPHONE sessions emit
//! dummy inner-handshake records of those lengths after ClientFinished so the
//! outer sizes match. Inner type stays `0x16` so PAYPHONE frames are not eaten.

use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use rustls::{
    ClientConfig, DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::TlsConnector;

const DEST_TIMEOUT: Duration = Duration::from_secs(8);
const DRAIN_WAIT: Duration = Duration::from_millis(800);
const CCS: &[u8] = &[0x14, 0x03, 0x03, 0x00, 0x01, 0x01];

/// `alpn`: 0 = none, 1 = `http/1.1`, 2 = `h2` (Xray's three dest probes).
pub async fn probe_post_handshake_records_alpn(dest: &str, sni: &str, alpn: u8) -> Vec<usize> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let Ok(Ok(stream)) = timeout(DEST_TIMEOUT, TcpStream::connect(dest)).await else {
        return Vec::new();
    };
    let _ = stream.set_nodelay(true);

    let lens = Arc::new(Mutex::new(Vec::new()));
    let spy = RecordSpy::new(stream, Arc::clone(&lens));
    let Ok(name) = ServerName::try_from(sni.to_string()) else {
        return Vec::new();
    };

    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerify))
        .with_no_client_auth();
    config.alpn_protocols = match alpn {
        2 => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        1 => vec![b"http/1.1".to_vec()],
        _ => Vec::new(),
    };

    let connector = TlsConnector::from(Arc::new(config));
    let Ok(Ok(mut tls)) = timeout(DEST_TIMEOUT, connector.connect(name, spy)).await else {
        return lock_vec(&lens);
    };

    let mut buf = [0u8; 32];
    let _ = timeout(DRAIN_WAIT, tls.read(&mut buf)).await;
    lock_vec(&lens)
}

fn lock_vec(lens: &Arc<Mutex<Vec<usize>>>) -> Vec<usize> {
    lens.lock().map(|guard| guard.clone()).unwrap_or_default()
}

struct RecordSpy {
    inner: TcpStream,
    ccs_sent: bool,
    write_tail: Vec<u8>,
    leftover: Vec<u8>,
    lens: Arc<Mutex<Vec<usize>>>,
}

impl RecordSpy {
    fn new(inner: TcpStream, lens: Arc<Mutex<Vec<usize>>>) -> Self {
        Self {
            inner,
            ccs_sent: false,
            write_tail: Vec::new(),
            leftover: Vec::new(),
            lens,
        }
    }

    fn note_write(&mut self, buf: &[u8]) {
        if self.ccs_sent {
            return;
        }

        self.write_tail.extend_from_slice(buf);
        if self
            .write_tail
            .windows(CCS.len())
            .any(|window| window == CCS)
        {
            self.ccs_sent = true;
        }

        if self.write_tail.len() > CCS.len() - 1 {
            let keep = CCS.len() - 1;
            self.write_tail.drain(..self.write_tail.len() - keep);
        }
    }

    fn note_read(&mut self, buf: &[u8]) {
        if !self.ccs_sent || buf.is_empty() {
            return;
        }

        self.leftover.extend_from_slice(buf);

        loop {
            if self.leftover.len() < 5 {
                break;
            }

            let len = u16::from_be_bytes([self.leftover[3], self.leftover[4]]) as usize;
            let total = 5 + len;

            if total > 16 * 1024 + 256 || self.leftover.len() < total {
                break;
            }

            if self.leftover[0] == 0x17
                && let Ok(mut guard) = self.lens.lock()
            {
                guard.push(total);
            }

            self.leftover.drain(..total);
        }
    }
}

impl AsyncRead for RecordSpy {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let new = buf.filled()[before..].to_vec();
                self.note_read(&new);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl AsyncWrite for RecordSpy {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let n = match Pin::new(&mut self.inner).poll_write(cx, buf)? {
            Poll::Ready(n) => n,
            Poll::Pending => return Poll::Pending,
        };
        self.note_write(&buf[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Debug)]
struct SkipServerVerify;

impl ServerCertVerifier for SkipServerVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn fake_tls_record(typ: u8, total_len: usize) -> Vec<u8> {
        let body = total_len - 5;
        let mut record = vec![typ, 0x03, 0x03, (body >> 8) as u8, body as u8];
        record.resize(total_len, 0);
        record
    }

    #[tokio::test]
    async fn spy_counts_app_records_after_ccs() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let mut ccs = [0u8; 6];
            tcp.read_exact(&mut ccs).await.unwrap();
            tcp.write_all(&fake_tls_record(0x17, 80)).await.unwrap();
            tcp.write_all(&fake_tls_record(0x17, 120)).await.unwrap();
            tcp.flush().await.unwrap();
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let lens = Arc::new(Mutex::new(Vec::new()));
        let mut spy = RecordSpy::new(stream, Arc::clone(&lens));
        spy.write_all(CCS).await.unwrap();

        let mut buf = [0u8; 256];
        let mut got = 0usize;
        while got < 200 {
            let n = spy.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            got += n;
        }

        assert_eq!(lock_vec(&lens), vec![80, 120]);
        server.await.unwrap();
    }
}
