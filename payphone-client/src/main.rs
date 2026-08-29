use std::{
    env, fs,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    path::Path,
    time::Duration,
};

use bytes::Bytes;
use quinn::Connection;

use tokio::{sync::mpsc, time};

use payphone_core::{
    DEFAULT_PORT, DEFAULT_TCP_PORT, Frame, FrameType, PROTOCOL_VERSION,
    access_denied_dude::AccessDeniedDude,
    all_good_dude::{AllGoodDude, SERVER_NONCE_SIZE, SESSION_ID_SIZE},
    back_again_dude::BackAgainDude,
    rekey::Rekey,
    still_good_dude::StillGoodDude,
    whats_up_dude::{CAP_DNS, CAP_IPV4, CAP_IPV6, CAP_RESUME, CAP_ROAMING, WhatsUpDude},
};

use payphone_transport::{
    client::create_client_endpoint,
    https_front::{TlsClientSession, read_payphone_frame},
    identity::SERVER_NAME,
    obfuscation::ObfuscationKey,
};

mod matrix;
mod tunnel;

use tunnel::{QuicShutdown, TunnelExit, VpnSink, run_tunnel};

// =============================================================
// CONFIG
// =============================================================

const CLIENT_VERSION: u16 = 1;

const CLIENT_CAPABILITIES: u32 = CAP_IPV4 | CAP_IPV6 | CAP_DNS | CAP_RESUME | CAP_ROAMING;

const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

//
// Джиттер keepalive: строго периодический PING (было ровно 10с)
// сам по себе почти подпись для DPI на простое соединение —
// мелкий пакет через фиксированный интервал, PONG в ответ.
// Реальный интервал каждый раз случаен в [PING_INTERVAL_MIN,
// PING_INTERVAL_MIN + PING_INTERVAL_JITTER).
//
const PING_INTERVAL_MIN: Duration = Duration::from_secs(7);

const PING_INTERVAL_JITTER: Duration = Duration::from_secs(7);

const SESSION_FILE: &str = ".payphone-session";

const SUBSCRIPTION_FILE: &str = "subscription.token";

// =============================================================
// SAVED / ACTIVE SESSION
// =============================================================

struct SavedSession {
    session_id: [u8; SESSION_ID_SIZE],

    resume_token: [u8; SERVER_NONCE_SIZE],
}

#[derive(Clone)]
pub(crate) struct ActiveSession {
    session_id: [u8; SESSION_ID_SIZE],

    assigned_ipv4: [u8; 4],

    mtu: u16,

    capabilities: u32,
}

// =============================================================
// SESSION FILE
// =============================================================

pub(crate) fn save_session(
    session_id: [u8; SESSION_ID_SIZE],

    resume_token: [u8; SERVER_NONCE_SIZE],
) -> std::io::Result<()> {
    let mut data = Vec::with_capacity(SESSION_ID_SIZE + SERVER_NONCE_SIZE);

    data.extend_from_slice(&session_id);

    data.extend_from_slice(&resume_token);

    fs::write(SESSION_FILE, data)
}

fn load_session() -> Option<SavedSession> {
    let data = fs::read(SESSION_FILE).ok()?;

    if data.len() != SESSION_ID_SIZE + SERVER_NONCE_SIZE {
        return None;
    }

    let mut session_id = [0u8; SESSION_ID_SIZE];

    session_id.copy_from_slice(&data[..SESSION_ID_SIZE]);

    let mut resume_token = [0u8; SERVER_NONCE_SIZE];

    resume_token.copy_from_slice(&data[SESSION_ID_SIZE..]);

    Some(SavedSession {
        session_id,
        resume_token,
    })
}

pub(crate) fn forget_session() {
    let _ = fs::remove_file(SESSION_FILE);
}

// =============================================================
// RECEIVE ONE FRAME
// =============================================================

async fn receive_frame(connection: &Connection) -> Result<Frame, Box<dyn std::error::Error>> {
    let bytes = time::timeout(RESPONSE_TIMEOUT, connection.read_datagram()).await??;

    Ok(Frame::decode(bytes)?)
}

trait HandshakeIo {
    async fn send_wait(&self, bytes: Bytes) -> Result<(), Box<dyn std::error::Error>>;

    async fn read_frame(&mut self) -> Result<Frame, Box<dyn std::error::Error>>;
}

impl HandshakeIo for Connection {
    async fn send_wait(&self, bytes: Bytes) -> Result<(), Box<dyn std::error::Error>> {
        self.send_datagram_wait(bytes).await?;

        Ok(())
    }

    async fn read_frame(&mut self) -> Result<Frame, Box<dyn std::error::Error>> {
        receive_frame(self).await
    }
}

impl HandshakeIo for TlsClientSession {
    async fn send_wait(&self, bytes: Bytes) -> Result<(), Box<dyn std::error::Error>> {
        self.send_frame_bytes(&bytes).await?;

        Ok(())
    }

    async fn read_frame(&mut self) -> Result<Frame, Box<dyn std::error::Error>> {
        Ok(self.recv_frame().await?)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TransportKind {
    Quic,
    Tls,
}

fn transport_kind() -> Result<TransportKind, Box<dyn std::error::Error>> {
    let value = env::var("PAYPHONE_TRANSPORT").unwrap_or_else(|_| "quic".into());

    match value.to_ascii_lowercase().as_str() {
        "quic" | "udp" => Ok(TransportKind::Quic),

        "tls" | "https" | "tcp" => Ok(TransportKind::Tls),

        other => Err(format!("unknown PAYPHONE_TRANSPORT={other}; use quic or tls").into()),
    }
}

fn resolve_server_addr(setting: &str) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    setting
        .to_socket_addrs()
        .map_err(|error| {
            format!("cannot resolve PAYPHONE_SERVER_ADDR {setting}: {error}")
        })?
        .next()
        .ok_or_else(|| format!("PAYPHONE_SERVER_ADDR {setting} resolved to no address").into())
}

fn tls_connect_address(
    quic_address: SocketAddr,
) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    if let Ok(setting) = env::var("PAYPHONE_TCP_SERVER_ADDR") {
        return resolve_server_addr(&setting);
    }

    if quic_address.port() == DEFAULT_PORT {
        Ok(SocketAddr::new(quic_address.ip(), DEFAULT_TCP_PORT))
    } else {
        Ok(quic_address)
    }
}

// =============================================================
// RESUME
// =============================================================

async fn try_resume<I: HandshakeIo>(
    io: &mut I,

    saved: SavedSession,
) -> Result<Option<ActiveSession>, Box<dyn std::error::Error>> {
    matrix::status("Back again, dude?");

    let message = BackAgainDude::new(saved.session_id, saved.resume_token);

    let frame = Frame {
        version: PROTOCOL_VERSION,

        frame_type: FrameType::BackAgainDude,

        flags: 0,

        sequence: 1,

        payload: message.encode(),
    };

    io.send_wait(frame.encode()).await?;

    let frame = match time::timeout(Duration::from_secs(2), io.read_frame()).await {
        Ok(Ok(frame)) => frame,

        _ => {
            return Ok(None);
        }
    };

    match frame.frame_type {
        FrameType::StillGoodDude => {
            let message = StillGoodDude::decode(frame.payload)?;

            if message.session_id != saved.session_id {
                return Ok(None);
            }

            matrix::status("Still good, dude.");

            rotate_resume_token(io, saved.session_id).await;

            Ok(Some(ActiveSession {
                session_id: message.session_id,

                assigned_ipv4: message.assigned_ipv4,

                mtu: message.mtu,

                capabilities: message.capabilities,
            }))
        }

        FrameType::AccessDeniedDude => {
            let denied = AccessDeniedDude::decode(frame.payload)?;

            println!("Resume denied: {:?}", denied.reason);

            Ok(None)
        }

        _ => Ok(None),
    }
}

// =============================================================
// NEW SESSION
// =============================================================

async fn create_new_session<I: HandshakeIo>(
    io: &mut I,
) -> Result<ActiveSession, Box<dyn std::error::Error>> {
    //
    // Настоящий подписочный token.
    //
    let token = fs::read(SUBSCRIPTION_FILE)
        .map_err(|error| format!("cannot read {}: {}", SUBSCRIPTION_FILE, error))?;

    let whats_up = WhatsUpDude::new(CLIENT_VERSION, CLIENT_CAPABILITIES, Bytes::from(token));

    let frame = Frame {
        version: PROTOCOL_VERSION,

        frame_type: FrameType::WhatsUpDude,

        flags: 0,

        sequence: 1,

        payload: whats_up.encode(),
    };

    matrix::status("What's up, dude?");

    io.send_wait(frame.encode()).await?;

    let response = time::timeout(RESPONSE_TIMEOUT, io.read_frame()).await??;

    let all_good = match response.frame_type {
        FrameType::AllGoodDude => AllGoodDude::decode(response.payload)?,

        FrameType::AccessDeniedDude => {
            let denied = AccessDeniedDude::decode(response.payload)?;

            return Err(format!("PAYPHONE access denied: {:?}", denied.reason).into());
        }

        other => {
            return Err(format!("unexpected handshake frame: {:?}", other).into());
        }
    };

    save_session(all_good.session_id, all_good.server_nonce)?;

    rotate_resume_token(io, all_good.session_id).await;

    matrix::status("All good, dude.");

    Ok(ActiveSession {
        session_id: all_good.session_id,

        assigned_ipv4: all_good.assigned_ipv4,

        mtu: all_good.mtu,

        capabilities: all_good.capabilities,
    })
}

async fn establish_session<I: HandshakeIo>(
    io: &mut I,
) -> Result<ActiveSession, Box<dyn std::error::Error>> {
    if Path::new(SESSION_FILE).exists() {
        match load_session() {
            Some(saved) => match try_resume(io, saved).await? {
                Some(session) => {
                    matrix::status("PAYPHONE SESSION RESUMED");

                    Ok(session)
                }

                None => {
                    let _ = fs::remove_file(SESSION_FILE);

                    create_new_session(io).await
                }
            },

            None => create_new_session(io).await,
        }
    } else {
        create_new_session(io).await
    }
}

async fn rotate_resume_token<I: HandshakeIo>(
    io: &mut I,
    session_id: [u8; SESSION_ID_SIZE],
) {
    let request = Frame {
        version: PROTOCOL_VERSION,
        frame_type: FrameType::Rekey,
        flags: 0,
        sequence: 2,
        payload: Rekey::request(session_id).encode(),
    };

    if io.send_wait(request.encode()).await.is_err() {
        return;
    }

    let Ok(Ok(frame)) = time::timeout(Duration::from_secs(2), io.read_frame()).await else {
        return;
    };

    let Ok(Rekey::Token {
        session_id: id,
        nonce,
    }) = Rekey::decode(frame.payload)
    else {
        return;
    };

    if id != session_id {
        return;
    }

    let _ = save_session(session_id, nonce);

    let confirm = Frame {
        version: PROTOCOL_VERSION,
        frame_type: FrameType::Rekey,
        flags: 0,
        sequence: 3,
        payload: Rekey::token(session_id, nonce).encode(),
    };

    let _ = io.send_wait(confirm.encode()).await;

    if let Ok(Ok(frame)) = time::timeout(Duration::from_secs(2), io.read_frame()).await {
        if let Ok(Rekey::Token {
            session_id: id,
            nonce,
        }) = Rekey::decode(frame.payload)
        {
            if id == session_id {
                let _ = save_session(session_id, nonce);
            }
        }
    }
}

// =============================================================
// KEEPALIVE JITTER
// =============================================================

pub(crate) fn random_ping_interval() -> Duration {
    use rand_core::{OsRng, TryRngCore};

    let mut jitter_bytes = [0u8; 2];

    //
    // OsRng не должен падать в нормальных условиях; при сбое
    // просто используем минимальный интервал без джиттера —
    // это не security-критичный путь.
    //
    let _ = OsRng.try_fill_bytes(&mut jitter_bytes);

    let jitter_fraction = u16::from_be_bytes(jitter_bytes) as u64;

    let jitter = PING_INTERVAL_JITTER.as_millis() as u64 * jitter_fraction / u16::MAX as u64;

    PING_INTERVAL_MIN + Duration::from_millis(jitter)
}

// =============================================================
// MAIN
// =============================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    //
    // Подхватываем .env, если он есть.
    //
    // Переменные, уже выставленные в окружении
    // (например, Docker Compose environment:),
    // остаются в приоритете.
    //
    dotenvy::dotenv().ok();

    //
    // По умолчанию — localhost, как раньше.
    //
    // В Docker Compose PAYPHONE_SERVER_ADDR=payphone-server:40404,
    // имя сервиса резолвится через Docker DNS.
    //
    // TLS-имя (SERVER_NAME) остаётся "localhost",
    // потому что dev-сертификат всегда выпущен на это имя.
    //
    let transport = transport_kind()?;

    let server_addr_setting =
        env::var("PAYPHONE_SERVER_ADDR").unwrap_or_else(|_| format!("127.0.0.1:{}", DEFAULT_PORT));

    let server_address = resolve_server_addr(&server_addr_setting)?;

    //
    // Тот же общий пароль обфускации, что и на сервере —
    // см. payphone_transport::obfuscation. TLS/HTTPS front does
    // not XOR the TCP stream; the secret is still required so
    // one .env works for both transports.
    //
    let obfuscation_passphrase = env::var("PAYPHONE_OBFS_PSK").map_err(
        |_| "PAYPHONE_OBFS_PSK is not set; use the same secret configured on the server",
    )?;

    payphone_transport::obfuscation::validate_passphrase(&obfuscation_passphrase)?;

    let obfuscation_key = ObfuscationKey::from_passphrase(&obfuscation_passphrase);

    let dev_mode = env::var("PAYPHONE_DEV_MODE")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    matrix::rain_intro();

    matrix::banner();

    let bind_iface = payphone_tun::routing::default_physical_interface();

    let bind_ip = payphone_tun::routing::default_outbound_ipv4().map(IpAddr::V4);

    let quic_endpoint = match transport {
        TransportKind::Quic => Some(create_client_endpoint(
            obfuscation_key,
            dev_mode,
            bind_ip,
            bind_iface.as_deref(),
        )?),

        TransportKind::Tls => None,
    };

    let mut connected_once = false;

    loop {
        let session = match transport {
            TransportKind::Quic => {
                let endpoint = quic_endpoint.as_ref().expect("QUIC endpoint");

                connect_quic(endpoint, server_address).await
            }

            TransportKind::Tls => connect_tls(server_address).await,
        };

        let (active, sink, incoming, quic, tunnel_host) = match session {
            Ok(parts) => parts,

            Err(error) if connected_once => {
                matrix::status(&format!("Reconnect failed ({error}), retrying"));

                time::sleep(Duration::from_secs(1)).await;

                continue;
            }

            Err(error) => return Err(error),
        };

        connected_once = true;

        matrix::status(&format!(
            "VPN IPv4: {}.{}.{}.{}",
            active.assigned_ipv4[0],
            active.assigned_ipv4[1],
            active.assigned_ipv4[2],
            active.assigned_ipv4[3],
        ));

        matrix::status(&format!("Capabilities: {}", active.capabilities));

        match run_tunnel(active, tunnel_host, sink, incoming, quic).await? {
            TunnelExit::Stopped => return Ok(()),

            TunnelExit::Denied(reason) => return Err(reason.into()),

            TunnelExit::Disconnected => {
                matrix::status("Link lost, reconnecting");

                time::sleep(Duration::from_millis(400)).await;
            }
        }
    }
}

const INCOMING_FRAMES: usize = 1024;

async fn connect_quic(
    endpoint: &quinn::Endpoint,
    server_address: SocketAddr,
) -> Result<
    (
        ActiveSession,
        VpnSink,
        mpsc::Receiver<Frame>,
        Option<QuicShutdown>,
        SocketAddr,
    ),
    Box<dyn std::error::Error>,
> {
    let mut connection = endpoint.connect(server_address, SERVER_NAME)?.await?;

    matrix::status("QUIC + TLS 1.3 connected");

    let active = establish_session(&mut connection).await?;

    let (tx, rx) = mpsc::channel(INCOMING_FRAMES);

    let reader = connection.clone();

    tokio::spawn(async move {
        loop {
            match reader.read_datagram().await {
                Ok(bytes) => {
                    if let Ok(frame) = Frame::decode(bytes) {
                        if tx.send(frame).await.is_err() {
                            break;
                        }
                    }
                }

                Err(_) => break,
            }
        }
    });

    Ok((
        active,
        VpnSink::Quic(connection.clone()),
        rx,
        Some(QuicShutdown { connection }),
        server_address,
    ))
}

async fn connect_tls(
    server_address: SocketAddr,
) -> Result<
    (
        ActiveSession,
        VpnSink,
        mpsc::Receiver<Frame>,
        Option<QuicShutdown>,
        SocketAddr,
    ),
    Box<dyn std::error::Error>,
> {
    let tls_address = tls_connect_address(server_address)?;

    let mut session = TlsClientSession::connect(tls_address).await?;

    matrix::status("TLS 1.3 connected (HTTPS front)");

    let active = establish_session(&mut session).await?;

    let (mut reader, writer) = session.into_split();

    let (tx, rx) = mpsc::channel(INCOMING_FRAMES);

    tokio::spawn(async move {
        loop {
            match read_payphone_frame(&mut reader).await {
                Ok(frame) => {
                    if tx.send(frame).await.is_err() {
                        break;
                    }
                }

                Err(_) => break,
            }
        }
    });

    Ok((active, VpnSink::Tls(writer), rx, None, tls_address))
}
