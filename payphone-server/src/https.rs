use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use bytes::Bytes;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{RwLock, mpsc},
};
use tokio_rustls::TlsAcceptor;

use payphone_core::HEADER_SIZE;
use payphone_transport::{
    https_front::{
        finish_payphone_frame, looks_like_http, read_payphone_frame, serve_camouflage_http,
        write_payphone_bytes,
    },
    reality::{
        ClientHelloView, PrefixedStream, RealityAccept, RealityServerConfig, Tls13Stream,
        accept as reality_accept, read_tls_record,
    },
    tls::ServerTlsRuntime,
};
use payphone_tun::SharedTun;

use crate::{
    handler::{PayphoneVerifier, handle_frame},
    session::{ClientLink, SessionManager},
};

pub async fn run(
    bind: SocketAddr,
    sessions: Arc<RwLock<SessionManager>>,
    verifier: Arc<PayphoneVerifier>,
    tun: SharedTun,
    stream_ids: Arc<AtomicU64>,
    tls: ServerTlsRuntime,
    reality: Option<RealityServerConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(bind).await?;

    if let Some(reality) = &reality {
        reality.spawn_post_handshake_probe();
        let local = if reality.local_names.is_empty() {
            "probes splice (no local name)".to_string()
        } else {
            format!("local {} keep landing", reality.local_names.join(","))
        };
        println!(
            "PAYPHONE HTTPS front: {bind} (REALITY dest {}, {local})",
            reality.dest
        );
    } else if tls.tls.acme_enabled() {
        println!(
            "PAYPHONE HTTPS front: {bind} (Let's Encrypt {}, landing + tunnel)",
            tls.tls.acme_domain.as_deref().unwrap_or("?")
        );
    } else {
        println!("PAYPHONE HTTPS front: {bind} (site for browsers, tunnel for clients)");
    }

    loop {
        let (tcp, peer) = listener.accept().await?;

        let _ = tcp.set_nodelay(true);

        let tls = tls.clone();
        let sessions = Arc::clone(&sessions);
        let verifier = Arc::clone(&verifier);
        let tun = Arc::clone(&tun);
        let stream_ids = Arc::clone(&stream_ids);
        let reality = reality.clone();

        tokio::spawn(async move {
            if let Err(error) =
                serve_connection(tcp, peer, tls, sessions, verifier, tun, stream_ids, reality).await
            {
                eprintln!("PAYPHONE HTTPS front {peer}: {error}");
            }
        });
    }
}

async fn serve_connection(
    tcp: tokio::net::TcpStream,
    peer: SocketAddr,
    tls: ServerTlsRuntime,
    sessions: Arc<RwLock<SessionManager>>,
    verifier: Arc<PayphoneVerifier>,
    tun: SharedTun,
    stream_ids: Arc<AtomicU64>,
    reality: Option<RealityServerConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(reality) = &reality {
        match reality_accept(tcp, reality).await? {
            RealityAccept::Vpn {
                stream,
                auth_key,
                server_name,
                dest_flight,
            } => {
                let tls =
                    Tls13Stream::accept(stream, &auth_key, &server_name, dest_flight.as_ref())
                        .await?;
                serve_tls_session(tls, peer, sessions, verifier, tun, stream_ids).await
            }
            RealityAccept::Local { stream, acme } => {
                accept_local(
                    stream, acme, &tls, peer, sessions, verifier, tun, stream_ids,
                )
                .await
            }
            RealityAccept::Spliced => Ok(()),
        }
    } else if tls.acme_challenge.is_some() {
        let mut tcp = tcp;
        let record = read_tls_record(&mut tcp).await?;
        let acme = ClientHelloView::parse(&record).is_some_and(|view| view.has_acme_alpn());
        let stream = PrefixedStream::new(record, tcp);
        accept_local(
            stream, acme, &tls, peer, sessions, verifier, tun, stream_ids,
        )
        .await
    } else {
        let stream = tls.acceptor.accept(tcp).await?;
        serve_tls_session(stream, peer, sessions, verifier, tun, stream_ids).await
    }
}

async fn accept_local(
    stream: PrefixedStream,
    acme: bool,
    tls: &ServerTlsRuntime,
    peer: SocketAddr,
    sessions: Arc<RwLock<SessionManager>>,
    verifier: Arc<PayphoneVerifier>,
    tun: SharedTun,
    stream_ids: Arc<AtomicU64>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let acceptor: &TlsAcceptor = if acme {
        tls.acme_challenge.as_ref().unwrap_or(&tls.acceptor)
    } else {
        &tls.acceptor
    };

    let mut accepted = acceptor.accept(stream).await?;

    if acme {
        let _ = accepted.shutdown().await;
        return Ok(());
    }

    serve_tls_session(accepted, peer, sessions, verifier, tun, stream_ids).await
}

async fn serve_tls_session<S>(
    mut stream: S,
    peer: SocketAddr,
    sessions: Arc<RwLock<SessionManager>>,
    verifier: Arc<PayphoneVerifier>,
    tun: SharedTun,
    stream_ids: Arc<AtomicU64>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut header = [0u8; HEADER_SIZE];

    stream.read_exact(&mut header).await?;

    if looks_like_http(header[0]) {
        serve_camouflage_http(&mut stream, &header).await?;

        return Ok(());
    }

    let first = finish_payphone_frame(&mut stream, header).await?;

    let stream_id = stream_ids.fetch_add(1, Ordering::Relaxed);

    let (tx, mut rx) = mpsc::channel::<Bytes>(1024);

    let (mut reader, mut writer) = tokio::io::split(stream);

    let write_task = tokio::spawn(async move {
        while let Some(bytes) = rx.recv().await {
            if write_payphone_bytes(&mut writer, &bytes).await.is_err() {
                break;
            }
        }
    });

    let link = ClientLink::Stream { id: stream_id, tx };

    handle_frame(
        link.clone(),
        peer,
        Arc::clone(&sessions),
        Arc::clone(&verifier),
        Arc::clone(&tun),
        first,
    )
    .await;

    loop {
        match read_payphone_frame(&mut reader).await {
            Ok(frame) => {
                handle_frame(
                    link.clone(),
                    peer,
                    Arc::clone(&sessions),
                    Arc::clone(&verifier),
                    Arc::clone(&tun),
                    frame,
                )
                .await;
            }

            Err(_) => break,
        }
    }

    write_task.abort();

    let detached = sessions.write().await.detach_by_stream_id(stream_id);

    if detached > 0 {
        println!("Detached {detached} TLS session(s) after TCP close");
    }

    Ok(())
}
