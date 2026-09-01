use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;

use ed25519_dalek::VerifyingKey;

use payphone_auth::{FileRevocationStore, SubscriptionVerifier, VerificationKeyRing};

use payphone_core::{
    DEFAULT_PORT, DEFAULT_TCP_PORT, Frame, FrameType, PROTOCOL_VERSION, data::Data,
};

use payphone_transport::{
    identity::load_certificates, obfuscation::ObfuscationKey,
    server::create_server_endpoint_with_runtime, tls::ServerTlsRuntime,
};

use payphone_tun::{create_server_tun, ipv4_destination};

use tokio::{signal, sync::RwLock, time};

mod dns;
mod handler;
mod https;
mod session;
mod settings;

use handler::handle_packet;
use session::SessionManager;
use settings::load_server_settings;

const CLEANUP_INTERVAL: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let settings = load_server_settings()?;

    let address: SocketAddr = settings
        .bind
        .parse()
        .map_err(|error| format!("invalid bind address {}: {}", settings.bind, error))?;

    payphone_transport::obfuscation::validate_passphrase(&settings.psk)?;

    let obfuscation_key = ObfuscationKey::from_passphrase(&settings.psk);

    let tls = settings.tls.clone();

    let tls_runtime = ServerTlsRuntime::start(&tls)?;

    let endpoint = create_server_endpoint_with_runtime(
        address,
        obfuscation_key,
        settings.dev_mode,
        &tls_runtime,
    )?;

    println!("PAYPHONE server: {}", address);

    //
    // Self-signed pin: dump the leaf as hex so the operator can
    // copy it into the client's pin file. A public-CA cert is
    // already trusted by --tls-ca system; don't spam a chain.
    //
    if tls.acme_enabled() {
        // ACME logs the domain and client flags in ServerTlsRuntime::start.
    } else if tls.uses_default_paths() {
        let certificates = load_certificates(&tls.cert_path)?;

        print!("PAYPHONE server certificate (hex, copy to client's pin file): ");

        for byte in certificates[0].as_ref() {
            print!("{:02x}", byte);
        }

        println!();
    } else {
        println!(
            "PAYPHONE TLS: {} + {} (SAN {}, reload on mtime)",
            tls.cert_path.display(),
            tls.key_path.display(),
            tls.sans.join(", ")
        );
    }

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

    let session_store = match settings.session_store {
        Some(path) => path,

        None if Path::new("/app/state").is_dir() => PathBuf::from("/app/state/sessions.bin"),

        None => PathBuf::from("payphone-sessions.bin"),
    };

    let sessions = Arc::new(RwLock::new(SessionManager::with_store(session_store)));

    let public_key = fs::read(&settings.auth_key)
        .map_err(|error| format!("cannot read {}: {error}", settings.auth_key.display()))?;

    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| "subscription public key must be 32 bytes")?;

    let public_key = VerifyingKey::from_bytes(&public_key)?;

    let mut keys = VerificationKeyRing::new();

    keys.insert(1, public_key);

    let verifier = Arc::new(SubscriptionVerifier::new(
        keys,
        FileRevocationStore::open(settings.revoke_file),
    ));

    //
    // TCP 443 camouflage: browsers get a landing page, PAYPHONE
    // clients speak the same frames over TLS after the handshake.
    // With REALITY enabled, probes are spliced to dest instead.
    // Set PAYPHONE_TCP_BIND_ADDR=off to disable.
    //
    let tcp_bind = match settings.tcp_bind.as_deref() {
        Some(value) if value == "off" || value.eq_ignore_ascii_case("false") => None,

        Some(value) => Some(
            value
                .parse::<SocketAddr>()
                .map_err(|error| format!("invalid TCP bind {value}: {error}"))?,
        ),

        None => {
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
        let tls_runtime = tls_runtime.clone();
        let reality = settings.reality.clone();

        tokio::spawn(async move {
            if let Err(error) = https::run(
                tcp_bind,
                sessions,
                verifier,
                tun,
                stream_ids,
                tls_runtime,
                reality,
            )
            .await
            {
                eprintln!("PAYPHONE HTTPS front stopped: {error}");
            }
        });
    }

    let dns_upstream = match settings.dns_upstream {
        Some(value) => value
            .parse::<SocketAddr>()
            .map_err(|error| format!("invalid DNS upstream {value}: {error}"))?,

        None => dns::default_upstream(),
    };

    tokio::spawn(async move {
        if let Err(error) = dns::run(dns_upstream).await {
            eprintln!("PAYPHONE DNS stub stopped: {error}");
        }
    });

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

                        let detached =
                            manager.detach_by_stable_id(
                                connection.stable_id(),
                            );

                        if detached > 0 {
                            println!(
                                "Detached {} session(s) after QUIC close",
                                detached
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
                            .and_then(
                                |session| {
                                    if !session
                                        .rate
                                        .allow(
                                            size as u64,
                                        )
                                    {
                                        return None;
                                    }

                                    Some(
                                        (
                                            session.id,
                                            session
                                                .link
                                                .clone(),
                                        )
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
