use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use bytes::Bytes;
use tokio::{
    io::AsyncReadExt,
    net::TcpListener,
    sync::{RwLock, mpsc},
};

use payphone_core::HEADER_SIZE;
use payphone_transport::https_front::{
    finish_payphone_frame, looks_like_http, read_payphone_frame, serve_camouflage_http,
    tls_server_acceptor, write_payphone_bytes,
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
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let acceptor = tls_server_acceptor().map_err(|error| error.to_string())?;

    let listener = TcpListener::bind(bind).await?;

    println!("PAYPHONE HTTPS front: {bind} (site for browsers, tunnel for clients)");

    loop {
        let (tcp, peer) = listener.accept().await?;

        let _ = tcp.set_nodelay(true);

        let acceptor = acceptor.clone();
        let sessions = Arc::clone(&sessions);
        let verifier = Arc::clone(&verifier);
        let tun = Arc::clone(&tun);
        let stream_ids = Arc::clone(&stream_ids);

        tokio::spawn(async move {
            if let Err(error) = serve_connection(
                tcp, peer, acceptor, sessions, verifier, tun, stream_ids,
            )
            .await
            {
                eprintln!("PAYPHONE HTTPS front {peer}: {error}");
            }
        });
    }
}

async fn serve_connection(
    tcp: tokio::net::TcpStream,
    peer: SocketAddr,
    acceptor: tokio_rustls::TlsAcceptor,
    sessions: Arc<RwLock<SessionManager>>,
    verifier: Arc<PayphoneVerifier>,
    tun: SharedTun,
    stream_ids: Arc<AtomicU64>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = acceptor.accept(tcp).await?;

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

    let link = ClientLink::Stream {
        id: stream_id,
        tx,
    };

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
