use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicU64},
    time::Duration,
};

use ed25519_dalek::VerifyingKey;

use payphone_auth::{FileRevocationStore, SubscriptionVerifier, VerificationKeyRing};

use payphone_core::{DEFAULT_PORT, DEFAULT_TCP_PORT};

use payphone_transport::{
    identity::load_certificates, obfuscation::ObfuscationKey,
    server::create_server_endpoint_with_runtime, tls::ServerTlsRuntime,
};

use payphone_tun::create_server_tun;

use tokio::{signal, sync::RwLock, time};

mod dns;
mod forward;
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

    println!("PAYPHONE server TUN: 10.77.0.1/16");

    //
    // Без этого пакеты доходят до TUN сервера, но дальше в
    // интернет не пересылаются — клиент подключится, но
    // реального доступа наружу не получит.
    //
    // Не фатально: если хостовое ядро/iptables не даёт это
    // настроить (например, нет nft/legacy совместимости или
    // недостаточно прав в этом окружении), VPN-сессии и
    // туннелирование внутри 10.77.0.0/16 всё равно должны
    // работать — падать из-за этого не нужно.
    //
    match payphone_tun::routing::enable_server_forwarding(
        payphone_tun::routing::PAYPHONE_SUBNET_CIDR,
    ) {
        Ok(()) => println!("PAYPHONE server forwarding/NAT enabled for 10.77.0.0/16"),

        Err(error) => eprintln!(
            "PAYPHONE server forwarding/NAT setup failed ({error}); \
             clients will only reach 10.77.0.0/16, not the wider internet"
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

    let revocations = Arc::new(FileRevocationStore::open(settings.revoke_file));
    let refresh_store = Arc::clone(&revocations);
    let mut revocation_worker = tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let store = Arc::clone(&refresh_store);
            if tokio::task::spawn_blocking(move || store.refresh())
                .await
                .is_err()
            {
                break;
            }
        }
    });
    let verifier = Arc::new(SubscriptionVerifier::new(keys, revocations));

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

    let mut forwarding = tokio::spawn(forward::run(
        Arc::clone(&tun),
        Arc::clone(&sessions),
        Arc::clone(&verifier),
    ));
    let mut cleanup = time::interval(CLEANUP_INTERVAL);
    cleanup.tick().await;

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

                        payphone_transport::log_quic_stats(&connection);

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


            result = &mut forwarding => {
                result??;
                break;
            }

            result = &mut revocation_worker => {
                result?;
                return Err("revocation worker stopped; refusing stale authorization".into());
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

                let invalid = manager.remove_invalid(verifier.as_ref());
                let removed = manager.remove_expired();
                drop(manager);
                for (session, reason) in invalid {
                    handler::send_access_denied(&session.link, 0, reason, session.subscription_expires_at).await;
                }

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

    forwarding.abort();
    revocation_worker.abort();
    endpoint.close(0u32.into(), b"server shutdown");

    endpoint.wait_idle().await;

    Ok(())
}
