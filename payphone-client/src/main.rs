use std::{
    env, fs,
    net::{SocketAddr, ToSocketAddrs},
    path::Path,
    time::Duration,
};

use bytes::Bytes;
use quinn::Connection;

use tokio::{signal, time};

use payphone_core::{
    DEFAULT_PORT, Frame, FrameType, PROTOCOL_VERSION,
    access_denied_dude::AccessDeniedDude,
    all_good_dude::{AllGoodDude, SERVER_NONCE_SIZE, SESSION_ID_SIZE},
    back_again_dude::BackAgainDude,
    data::Data,
    ping::Ping,
    pong::Pong,
    still_good_dude::StillGoodDude,
    whats_up_dude::{CAP_DNS, CAP_IPV4, CAP_IPV6, CAP_RESUME, CAP_ROAMING, WhatsUpDude},
};

use payphone_transport::{
    client::create_client_endpoint, identity::SERVER_NAME, obfuscation::ObfuscationKey,
};

use payphone_tun::{PAYPHONE_MTU, create_client_tun};

mod matrix;

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
struct ActiveSession {
    session_id: [u8; SESSION_ID_SIZE],

    assigned_ipv4: [u8; 4],

    mtu: u16,

    capabilities: u32,
}

// =============================================================
// SESSION FILE
// =============================================================

fn save_session(
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

// =============================================================
// RECEIVE ONE FRAME
// =============================================================

async fn receive_frame(connection: &Connection) -> Result<Frame, Box<dyn std::error::Error>> {
    let bytes = time::timeout(RESPONSE_TIMEOUT, connection.read_datagram()).await??;

    Ok(Frame::decode(bytes)?)
}

// =============================================================
// RESUME
// =============================================================

async fn try_resume(
    connection: &Connection,

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

    connection.send_datagram_wait(frame.encode()).await?;

    let response = match time::timeout(Duration::from_secs(2), connection.read_datagram()).await {
        Ok(Ok(bytes)) => bytes,

        _ => {
            return Ok(None);
        }
    };

    let frame = Frame::decode(response)?;

    match frame.frame_type {
        FrameType::StillGoodDude => {
            let message = StillGoodDude::decode(frame.payload)?;

            if message.session_id != saved.session_id {
                return Ok(None);
            }

            matrix::status("Still good, dude.");

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

async fn create_new_session(
    connection: &Connection,
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

    connection.send_datagram_wait(frame.encode()).await?;

    let response = receive_frame(connection).await?;

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

    matrix::status("All good, dude.");

    Ok(ActiveSession {
        session_id: all_good.session_id,

        assigned_ipv4: all_good.assigned_ipv4,

        mtu: all_good.mtu,

        capabilities: all_good.capabilities,
    })
}

// =============================================================
// KEEPALIVE JITTER
// =============================================================

fn random_ping_interval() -> Duration {
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
    let server_addr_setting =
        env::var("PAYPHONE_SERVER_ADDR").unwrap_or_else(|_| format!("127.0.0.1:{}", DEFAULT_PORT));

    let server_address: SocketAddr = server_addr_setting
        .to_socket_addrs()
        .map_err(|error| {
            format!(
                "cannot resolve PAYPHONE_SERVER_ADDR {}: {}",
                server_addr_setting, error
            )
        })?
        .next()
        .ok_or_else(|| {
            format!(
                "PAYPHONE_SERVER_ADDR {} resolved to no address",
                server_addr_setting
            )
        })?;

    //
    // Тот же общий пароль обфускации, что и на сервере —
    // см. payphone_transport::obfuscation.
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

    //
    // QUIC/TLS.
    //
    let endpoint = create_client_endpoint(obfuscation_key, dev_mode)?;

    let connection = endpoint.connect(server_address, SERVER_NAME)?.await?;

    matrix::status("QUIC + TLS 1.3 connected");

    //
    // Resume или новый handshake.
    //
    let active = if Path::new(SESSION_FILE).exists() {
        match load_session() {
            Some(saved) => match try_resume(&connection, saved).await? {
                Some(session) => {
                    matrix::status("PAYPHONE SESSION RESUMED");

                    session
                }

                None => {
                    let _ = fs::remove_file(SESSION_FILE);

                    create_new_session(&connection).await?
                }
            },

            None => create_new_session(&connection).await?,
        }
    } else {
        create_new_session(&connection).await?
    };

    matrix::status(&format!(
        "VPN IPv4: {}.{}.{}.{}",
        active.assigned_ipv4[0],
        active.assigned_ipv4[1],
        active.assigned_ipv4[2],
        active.assigned_ipv4[3],
    ));

    matrix::status(&format!("VPN MTU: {}", active.mtu));

    matrix::status(&format!("Capabilities: {}", active.capabilities));

    //
    // =========================================================
    // CREATE TUN
    // =========================================================
    //

    let tun = create_client_tun(
        active.assigned_ipv4,
        if active.mtu == 0 {
            PAYPHONE_MTU
        } else {
            active.mtu
        },
    )?;

    matrix::status("PAYPHONE TUN created");

    //
    // Без этого через TUN идёт только трафик к 10.77.0.0/24 —
    // весь остальной (браузер и т.д.) продолжает идти мимо VPN.
    // Guard живёт до конца main() и восстанавливает исходную
    // маршрутизацию при выходе (Ctrl+C, ошибка, паника).
    //
    let tun_name = tun.name()?;

    let _full_tunnel =
        match payphone_tun::routing::FullTunnelGuard::install(server_address, &tun_name) {
            Ok(guard) => {
                matrix::status(
                    "Full-tunnel routing enabled (all traffic now goes through PAYPHONE)",
                );

                matrix::tunnel_open_banner();

                Some(guard)
            }

            Err(error) => {
                eprintln!(
                    "Could not enable full-tunnel routing ({error}); \
                 only 10.77.0.0/24 will go through the VPN"
                );

                None
            }
        };

    matrix::status("Try: ping 10.77.0.1");

    //
    // Buffer настоящего IP packet.
    //
    let mut tun_buffer = vec![0u8; 65535];

    let mut packet_id: u64 = 1;

    let mut frame_sequence: u64 = 10;

    let mut ping_id: u64 = 1;

    let mut flow = matrix::FlowIndicator::new();

    //
    // =========================================================
    // VPN LOOP
    // =========================================================
    //

    loop {
        tokio::select! {
            //
            // ---------------------------------------------
            // TUN -> PAYPHONE -> QUIC
            // ---------------------------------------------
            //
            result =
                tun.recv(
                    &mut tun_buffer
                )
            => {
                let size =
                    result?;

                if size == 0 {
                    continue;
                }

                let payload =
                    Bytes::copy_from_slice(
                        &tun_buffer[
                            ..size
                        ]
                    );

                let data =
                    Data::new(
                        active.session_id,
                        packet_id,
                        payload,
                    );

                let frame =
                    Frame {
                        version:
                            PROTOCOL_VERSION,

                        frame_type:
                            FrameType::Data,

                        flags: 0,

                        sequence:
                            frame_sequence,

                        payload:
                            data.encode(),
                    };

                connection
                    .send_datagram_wait(
                        frame.encode()
                    )
                    .await?;

                flow.pulse('▸');

                packet_id =
                    packet_id
                        .wrapping_add(1);

                frame_sequence =
                    frame_sequence
                        .wrapping_add(1);
            }


            //
            // ---------------------------------------------
            // QUIC -> PAYPHONE -> TUN
            // ---------------------------------------------
            //
            result =
                connection
                    .read_datagram()
            => {
                let bytes =
                    result?;

                let frame =
                    match Frame::decode(
                        bytes
                    ) {
                        Ok(frame) => frame,

                        Err(error) => {
                            eprintln!(
                                "Invalid PAYPHONE frame: {}",
                                error
                            );

                            continue;
                        }
                    };

                match frame.frame_type {
                    FrameType::Data => {
                        let data =
                            Data::decode(
                                frame.payload
                            )?;

                        if data.session_id
                            != active.session_id
                        {
                            continue;
                        }

                        //
                        // Вот здесь реальный IP packet
                        // возвращается в macOS/Linux.
                        //
                        tun.send(
                            &data.payload
                        )
                        .await?;

                        flow.pulse('◂');
                    }

                    FrameType::Pong => {
                        let pong =
                            Pong::decode(
                                frame.payload
                            )?;

                        if pong.session_id
                            == active.session_id
                        {
                            println!(
                                "PONG {}",
                                pong.ping_id
                            );
                        }
                    }

                    FrameType::AccessDeniedDude => {
                        let denied =
                            AccessDeniedDude::decode(
                                frame.payload
                            )?;

                        return Err(
                            format!(
                                "PAYPHONE access revoked: {:?}",
                                denied.reason
                            )
                            .into()
                        );
                    }

                    _ => {}
                }
            }


            //
            // ---------------------------------------------
            // KEEPALIVE
            // ---------------------------------------------
            //
            //
            // Пересоздаётся заново на каждой итерации loop —
            // именно за счёт этого интервал каждый раз новый,
            // без ручного управления состоянием таймера.
            //
            _ =
                time::sleep(random_ping_interval())
            => {
                let ping =
                    Ping::new(
                        active.session_id,
                        ping_id,
                    );

                let frame =
                    Frame {
                        version:
                            PROTOCOL_VERSION,

                        frame_type:
                            FrameType::Ping,

                        flags: 0,

                        sequence:
                            frame_sequence,

                        payload:
                            ping.encode(),
                    };

                connection
                    .send_datagram_wait(
                        frame.encode()
                    )
                    .await?;

                ping_id =
                    ping_id
                        .wrapping_add(1);

                frame_sequence =
                    frame_sequence
                        .wrapping_add(1);
            }


            //
            // ---------------------------------------------
            // CTRL+C
            // ---------------------------------------------
            //
            _ =
                signal::ctrl_c()
            => {
                //
                // Перевод строки после хвоста "▸◂"-индикаторов
                // (они печатаются без \n).
                //
                println!();

                matrix::status(
                    "Stopping PAYPHONE VPN"
                );

                break;
            }
        }
    }

    connection.close(0u32.into(), b"client shutdown");

    endpoint.wait_idle().await;

    Ok(())
}
