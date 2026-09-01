use std::{io, sync::Arc};

use bytes::Bytes;
use rustls::{ClientConfig, ServerConfig, pki_types::ServerName};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf, split},
    net::TcpStream,
    sync::Mutex,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use payphone_core::{Frame, HEADER_SIZE, PROTOCOL_VERSION};

use crate::identity::{ClientTlsConfig, ServerTlsConfig, client_root_store, load_server_tls};

pub const HTTP_ALPN: &[u8] = b"http/1.1";

pub trait TlsIo: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> TlsIo for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub type TlsIoBox = Box<dyn TlsIo>;

fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub const CAMOUFLAGE_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PAYPHONE</title>
<style>
  html, body { margin: 0; background: #000; color: #00ff41; font-family: ui-monospace, monospace; }
  main { max-width: 40rem; margin: 12vh auto; padding: 0 1.5rem; }
  h1 { font-weight: 400; letter-spacing: 0.2em; }
  p { opacity: 0.8; }
</style>
</head>
<body>
<main>
<h1>PAYPHONE</h1>
<p>Follow the white rabbit.</p>
</main>
</body>
</html>
"#;

pub fn camouflage_http_response() -> Vec<u8> {
    let body = CAMOUFLAGE_HTML.as_bytes();

    let header = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         Cache-Control: no-store\r\n\
         \r\n",
        body.len()
    );

    let mut out = header.into_bytes();

    out.extend_from_slice(body);

    out
}

pub fn looks_like_http(first: u8) -> bool {
    first != PROTOCOL_VERSION
}

pub fn tls_server_acceptor(
    tls: &ServerTlsConfig,
) -> Result<TlsAcceptor, Box<dyn std::error::Error>> {
    ensure_crypto_provider();

    let (certificates, private_key) = load_server_tls(tls)?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)?;

    config.alpn_protocols = vec![HTTP_ALPN.to_vec()];

    Ok(TlsAcceptor::from(Arc::new(config)))
}

pub fn tls_client_connector(
    tls: &ClientTlsConfig,
) -> Result<TlsConnector, Box<dyn std::error::Error>> {
    ensure_crypto_provider();

    let roots = client_root_store(tls)?;

    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    config.alpn_protocols = vec![HTTP_ALPN.to_vec()];

    Ok(TlsConnector::from(Arc::new(config)))
}

pub fn tls_server_name(name: &str) -> Result<ServerName<'static>, Box<dyn std::error::Error>> {
    ServerName::try_from(name.to_string()).map_err(|error| error.into())
}

pub async fn read_payphone_frame<R>(reader: &mut R) -> io::Result<Frame>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; HEADER_SIZE];

    reader.read_exact(&mut header).await?;

    finish_payphone_frame(reader, header).await
}

pub async fn finish_payphone_frame<R>(
    reader: &mut R,
    header: [u8; HEADER_SIZE],
) -> io::Result<Frame>
where
    R: AsyncRead + Unpin,
{
    let payload_len = Frame::payload_len_from_header(&header).map_err(io::Error::other)?;

    let mut buffer = Vec::with_capacity(HEADER_SIZE + payload_len);

    buffer.extend_from_slice(&header);

    buffer.resize(HEADER_SIZE + payload_len, 0);

    reader.read_exact(&mut buffer[HEADER_SIZE..]).await?;

    Frame::decode(Bytes::from(buffer)).map_err(io::Error::other)
}

pub async fn write_payphone_bytes<W>(writer: &mut W, bytes: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(bytes).await?;

    writer.flush().await
}

pub async fn serve_camouflage_http<S>(stream: &mut S, prefix: &[u8]) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut request = prefix.to_vec();

    let mut chunk = [0u8; 1024];

    while request.len() < 32 * 1024 {
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }

        let size = stream.read(&mut chunk).await?;

        if size == 0 {
            break;
        }

        request.extend_from_slice(&chunk[..size]);
    }

    stream.write_all(&camouflage_http_response()).await?;

    stream.shutdown().await
}

pub struct TlsClientSession {
    read: ReadHalf<TlsIoBox>,

    write: Arc<Mutex<WriteHalf<TlsIoBox>>>,
}

#[derive(Clone)]
pub struct TlsFrameWriter {
    write: Arc<Mutex<WriteHalf<TlsIoBox>>>,
}

impl TlsClientSession {
    pub async fn connect(
        address: std::net::SocketAddr,
        tls: &ClientTlsConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let stream: TlsIoBox = if let Some(reality) = &tls.reality {
            Box::new(crate::reality::Tls13Client::connect(address, reality, tls).await?)
        } else {
            let tcp = TcpStream::connect(address).await?;

            tcp.set_nodelay(true)?;

            Box::new(
                tls_client_connector(tls)?
                    .connect(tls_server_name(&tls.server_name)?, tcp)
                    .await?,
            )
        };

        let (read, write) = split(stream);

        Ok(Self {
            read,
            write: Arc::new(Mutex::new(write)),
        })
    }

    pub async fn send_frame_bytes(&self, bytes: &[u8]) -> io::Result<()> {
        let mut writer = self.write.lock().await;

        write_payphone_bytes(&mut *writer, bytes).await
    }

    pub async fn recv_frame(&mut self) -> io::Result<Frame> {
        read_payphone_frame(&mut self.read).await
    }

    pub fn into_split(self) -> (ReadHalf<TlsIoBox>, TlsFrameWriter) {
        (self.read, TlsFrameWriter { write: self.write })
    }
}

impl TlsFrameWriter {
    pub async fn send_bytes(&self, bytes: &[u8]) -> io::Result<()> {
        let mut writer = self.write.lock().await;

        write_payphone_bytes(&mut *writer, bytes).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_probe_is_not_a_payphone_frame() {
        assert!(looks_like_http(b'G'));
        assert!(looks_like_http(b'P'));
        assert!(!looks_like_http(PROTOCOL_VERSION));
    }

    #[test]
    fn camouflage_page_mentions_the_rabbit() {
        let page = String::from_utf8(camouflage_http_response()).expect("ascii http");

        assert!(page.contains("HTTP/1.1 200 OK"));
        assert!(page.contains("Follow the white rabbit."));
    }
}
