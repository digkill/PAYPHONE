use std::{
    env, fs,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;

use ed25519_dalek::VerifyingKey;

use payphone_auth::{MemoryRevocationStore, SubscriptionVerifier, VerificationKeyRing};

use payphone_core::{
    DEFAULT_PORT, DEFAULT_TCP_PORT, Frame, FrameType, PROTOCOL_VERSION, data::Data,
};

use payphone_transport::{obfuscation::ObfuscationKey, server::create_server_endpoint};

use payphone_tun::{create_server_tun, ipv4_destination};

use tokio::{signal, sync::RwLock, time};

mod handler;
mod https;
mod session;

use handler::handle_packet;
use session::SessionManager;

const CLEANUP_INTERVAL: Duration = Duration::from_secs(5);

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
    // В Docker Compose PAYPHONE_BIND_ADDR=0.0.0.0:40404,
    // чтобы принимать соединения из других контейнеров.
    //
    let bind_addr =
        env::var("PAYPHONE_BIND_ADDR").unwrap_or_else(|_| format!("127.0.0.1:{}", DEFAULT_PORT));

    let address: SocketAddr = bind_addr
        .parse()
        .map_err(|error| format!("invalid PAYPHONE_BIND_ADDR {}: {}", bind_addr, error))?;

    //
    // Общий пароль для обфускации UDP-пакетов (см.
    // payphone_transport::obfuscation). Обязателен: без него
    // сервер и клиент не понимают друг друга на проводе, и
    // публичный дефолт в коде свёл бы защиту от DPI-пробинга
    // к нулю для любого, кто читает исходники.
    //
    let obfuscation_passphrase = env::var("PAYPHONE_OBFS_PSK").map_err(|_| {
        "PAYPHONE_OBFS_PSK is not set; generate a secret and set it identically on client and server"
    })?;

    payphone_transport::obfuscation::validate_passphrase(&obfuscation_passphrase)?;

    let obfuscation_key = ObfuscationKey::from_passphrase(&obfuscation_passphrase);

    //
    // Диагностическое логирование (сырые датаграммы до
    // деобфускации). Выключено по умолчанию — тишина в ответ
    // на нераспознанный трафик часть защиты от DPI-пробинга.
    //
    let dev_mode = env::var("PAYPHONE_DEV_MODE")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    //
    // =========================================================
    // QUIC
    // =========================================================
    //

    let endpoint = create_server_endpoint(address, obfuscation_key, dev_mode)?;

    println!("PAYPHONE server: {}", address);

    //
    // Печатаем собственный (само-подписанный, публичный) сертификат
    // в лог как hex. Сертификат — не секрет, в отличие от ключа,
    // который его подписал и который никуда не уходит с этой машины.
    //
    // Клиент пинит именно этот файл (`identity::CERT_PATH`), поэтому
    // при первом подключении к новому серверу оператору нужно
    // скопировать этот hex в `dev-certs/payphone-cert.der` на
    // клиентской машине:
    //
    //   echo <hex> | xxd -r -p > dev-certs/payphone-cert.der
    //
    let certificate_bytes = fs::read(payphone_transport::identity::CERT_PATH)?;

    print!("PAYPHONE server certificate (hex, copy to client's dev-certs/payphone-cert.der): ");

    for byte in &certificate_bytes {
        print!("{:02x}", byte);
    }

    println!();

    //
    // =========================================================
    // TUN
    // =========================================================
    //

    let tun = create_server_tun()?;

    println!("PAYPHONE server TUN: 10.77.0.1/24");

    //
    // Без этого пакеты доходят до TUN сервера, но дальше в
    // интернет не пересылаются — клиент подключится, но
    // реального доступа наружу не получит.
    //
    // Не фатально: если хостовое ядро/iptables не даёт это
    // настроить (например, нет nft/legacy совместимости или
    // недостаточно прав в этом окружении), VPN-сессии и
    // туннелирование внутри 10.77.0.0/24 всё равно должны
    // работать — падать из-за этого не нужно.
    //
    match payphone_tun::routing::enable_server_forwarding(
        payphone_tun::routing::PAYPHONE_SUBNET_CIDR,
    ) {
        Ok(()) => println!("PAYPHONE server forwarding/NAT enabled for 10.77.0.0/24"),

        Err(error) => eprintln!(
            "PAYPHONE server forwarding/NAT setup failed ({error}); \
             clients will only reach 10.77.0.0/24, not the wider internet"
        ),
    }

    //
    // =========================================================
    // SESSIONS
    // =========================================================
    //

    let sessions = Arc::new(RwLock::new(SessionManager::new()));

    //
    // =========================================================
    // AUTH
    // =========================================================
    //

    let public_key = fs::read("auth-keys/subscription-public.key")?;

    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| "subscription public key must be 32 bytes")?;

    let public_key = VerifyingKey::from_bytes(&public_key)?;

    let mut keys = VerificationKeyRing::new();

    keys.insert(1, public_key);

    let verifier = Arc::new(SubscriptionVerifier::new(
        keys,
        MemoryRevocationStore::new(),
    ));

    //
    // TCP 443 camouflage: browsers get a landing page, PAYPHONE
    // clients speak the same frames over TLS after the handshake.
    // Set PAYPHONE_TCP_BIND_ADDR=off to disable.
    //
    let tcp_bind = match env::var("PAYPHONE_TCP_BIND_ADDR") {
        Ok(value) if value == "off" || value.eq_ignore_ascii_case("false") => None,

        Ok(value) => Some(
            value
                .parse::<SocketAddr>()
                .map_err(|error| format!("invalid PAYPHONE_TCP_BIND_ADDR {value}: {error}"))?,
        ),

        Err(_) => {
            let tcp_port = if address.port() == DEFAULT_PORT {
                DEFAULT_TCP_PORT
            } else {
                address.port()
            };

            Some(SocketAddr::new(address.ip(), tcp_port))
        }
    };

    let stream_ids = Arc::new(AtomicU64::new(1));

    if let Some(tcp_bind) = tcp_bind {
        let sessions = Arc::clone(&sessions);
        let verifier = Arc::clone(&verifier);
        let tun = Arc::clone(&tun);
        let stream_ids = Arc::clone(&stream_ids);

        tokio::spawn(async move {
            if let Err(error) = https::run(tcp_bind, sessions, verifier, tun, stream_ids).await {
                eprintln!("PAYPHONE HTTPS front stopped: {error}");
            }
        });
    }

    //
    // =========================================================
    // SERVER -> CLIENT PACKET COUNTER
    // =========================================================
    //

    let server_packet_id = Arc::new(AtomicU64::new(1));

    let mut cleanup = time::interval(CLEANUP_INTERVAL);

    cleanup.tick().await;

    let mut tun_buffer = vec![0u8; 65535];

    println!("PAYPHONE VPN ready");

    loop {
        tokio::select! {
            //
            // =================================================
            // NEW QUIC CONNECTION
            // =================================================
            //
            incoming =
                endpoint.accept()
            => {
                let Some(incoming) =
                    incoming
                else {
                    break;
                };

                let sessions =
                    Arc::clone(
                        &sessions
                    );

                let verifier =
                    Arc::clone(
                        &verifier
                    );

                let tun =
                    Arc::clone(
                        &tun
                    );

                tokio::spawn(
                    async move {
                        let connection =
                            match incoming.await {
                                Ok(connection) =>
                                    connection,

                                Err(error) => {
                                    eprintln!(
                                        "QUIC handshake failed: {}",
                                        error
                                    );

                                    return;
                                }
                            };

                        println!(
                            "Client connected: {}",
                            connection.remote_address()
                        );

                        loop {
                            let packet =
                                match connection
                                    .read_datagram()
                                    .await
                                {
                                    Ok(packet) =>
                                        packet,

                                    Err(_) => {
                                        let mut manager =
                                            sessions.write().await;

                                        let removed =
                                            manager.remove_by_stable_id(
                                                connection.stable_id(),
                                            );

                                        if removed > 0 {
                                            println!(
                                                "Dropped {} session(s) after QUIC close",
                                                removed
                                            );
                                        }

                                        break;
                                    }
                                };

                            let sessions =
                                Arc::clone(
                                    &sessions
                                );

                            let verifier =
                                Arc::clone(
                                    &verifier
                                );

                            let tun =
                                Arc::clone(
                                    &tun
                                );

                            let connection_clone =
                                connection.clone();

                            handle_packet(
                                connection_clone,
                                sessions,
                                verifier,
                                tun,
                                packet,
                            )
                            .await;
                        }
                    }
                );
            }


            //
            // =================================================
            // SERVER TUN -> PAYPHONE CLIENT
            // =================================================
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

                let packet =
                    &tun_buffer[
                        ..size
                    ];

                let Some(destination) =
                    ipv4_destination(
                        packet
                    )
                else {
                    //
                    // IPv6 добавим следующим слоем.
                    //
                    continue;
                };

                //
                // По destination VPN IP
                // находим Session.
                //
                let route =
                    {
                        let manager =
                            sessions
                                .read()
                                .await;

                        manager
                            .find_by_ipv4(
                                destination
                            )
                            .map(
                                |session| {
                                    (
                                        session.id,
                                        session
                                            .link
                                            .clone(),
                                    )
                                }
                            )
                    };

                let Some(
                    (
                        session_id,
                        link,
                    )
                ) = route
                else {
                    continue;
                };

                let id =
                    server_packet_id
                        .fetch_add(
                            1,
                            Ordering::Relaxed,
                        );

                let data =
                    Data::new(
                        session_id,
                        id,
                        Bytes::copy_from_slice(
                            packet
                        ),
                    );

                let frame =
                    Frame {
                        version:
                            PROTOCOL_VERSION,

                        frame_type:
                            FrameType::Data,

                        flags: 0,

                        sequence:
                            id,

                        payload:
                            data.encode(),
                    };

                let encoded = frame.encode();

                link.send(encoded).await;
            }


            //
            // =================================================
            // CLEANUP
            // =================================================
            //
            _ =
                cleanup.tick()
            => {
                let mut manager =
                    sessions
                        .write()
                        .await;

                let removed =
                    manager
                        .remove_expired();

                if removed > 0 {
                    println!(
                        "Removed {} expired session(s)",
                        removed
                    );
                }
            }


            //
            // =================================================
            // SHUTDOWN
            // =================================================
            //
            _ =
                signal::ctrl_c()
            => {
                break;
            }
        }
    }

    endpoint.close(0u32.into(), b"server shutdown");

    endpoint.wait_idle().await;

    Ok(())
}
