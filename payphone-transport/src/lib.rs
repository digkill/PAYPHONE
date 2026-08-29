pub mod client;
pub mod https_front;
pub mod identity;
pub mod obfuscated_socket;
pub mod obfuscation;
pub mod server;

use std::{sync::Arc, time::Duration};

use quinn::{AckFrequencyConfig, MtuDiscoveryConfig, TransportConfig, VarInt, congestion::BbrConfig};

/// QUIC transport for a long-lived VPN, not a short web request.
///
/// Quinn's defaults idle-out a quiet connection in 30s. PAYPHONE
/// keepalives are jittered around 7–15s, and a brief UDP blip
/// (Wi-Fi roam, NAT rebind, DPI drop) used to kill the session:
/// the client vanished, the server kept writing `connection lost`
/// into TUN→QUIC, and after `SESSION_TIMEOUT` the VPN address was
/// gone. Raise the idle ceiling and send QUIC-layer keepalives so
/// the connection survives those gaps.
pub fn vpn_transport_config() -> TransportConfig {
    let mut transport = TransportConfig::default();

    //
    // Quiet VPN + NAT/DPI blips. Quinn's 30s idle is far too
    // aggressive: a Wi-Fi roam or a 40s UDP hole punch gap used
    // to kill the QUIC connection while the TUN routes were still
    // up. 3 minutes of idle, with QUIC keepalives well under that.
    //
    transport.max_idle_timeout(Some(
        Duration::from_secs(180)
            .try_into()
            .expect("180s is within QUIC idle-timeout bounds"),
    ));

    transport.keep_alive_interval(Some(Duration::from_secs(3)));

    //
    // Quinn defaults to 333ms (RFC 9002) before the first sample.
    // A VPN to a nearby VPS is typically 20–80ms; starting that
    // pessimistic makes slow-start crawl and the tunnel feels
    // "protocol-slow" even on an empty path.
    //
    transport.initial_rtt(Duration::from_millis(50));

    //
    // Don't declare persistent congestion after a short DPI drop
    // or a single PTO burst — that collapses BBR's window and the
    // tunnel feels "dead" for seconds. Default is 3 PTOs.
    //
    transport.persistent_congestion_threshold(6);

    //
    // Wi-Fi reordering looks like loss at threshold 3. One extra
    // packet before fast-retransmit avoids spurious BBR backoff.
    //
    transport.packet_threshold(4);

    let mut mtu_discovery = MtuDiscoveryConfig::default();

    mtu_discovery.interval(Duration::from_secs(20));
    mtu_discovery.black_hole_cooldown(Duration::from_secs(10));
    mtu_discovery.upper_bound(1452);

    transport.mtu_discovery_config(Some(mtu_discovery));

    let mut ack_frequency = AckFrequencyConfig::default();

    ack_frequency.ack_eliciting_threshold(VarInt::from_u32(2));
    ack_frequency.max_ack_delay(Some(Duration::from_millis(10)));

    transport.ack_frequency_config(Some(ack_frequency));

    //
    // Cubic treats loss as congestion and backs off hard — inner
    // TCP then also backs off (double control loop). BBR paces to
    // measured bandwidth and recovers faster on Wi-Fi / DPI drops.
    //
    transport.congestion_controller_factory(Arc::new(BbrConfig::default()));

    transport.datagram_receive_buffer_size(Some(8 * 1024 * 1024));

    transport.datagram_send_buffer_size(8 * 1024 * 1024);

    //
    // ObfuscatedSocket now speaks GSO/GRO; leave Quinn's offload
    // on so bulk TUN traffic is one syscall per batch on Linux.
    //
    transport.enable_segmentation_offload(true);

    transport
}

pub fn vpn_transport() -> Arc<TransportConfig> {
    Arc::new(vpn_transport_config())
}

/// Queue a PAYPHONE datagram without waiting for congestion window.
///
/// Waiting (`send_datagram_wait`) serialized TUN reads behind QUIC
/// send, so one slow packet stalled the whole VPN. Datagrams are
/// unreliable anyway — if the buffer is full, older packets are
/// dropped and inner TCP/QUIC retransmits. Returns `false` when the
/// frame does not fit the current path MTU.
pub fn send_vpn_datagram(
    connection: &quinn::Connection,
    bytes: bytes::Bytes,
) -> Result<bool, quinn::ConnectionError> {
    if connection
        .max_datagram_size()
        .is_some_and(|max| bytes.len() > max)
    {
        return Ok(false);
    }

    match connection.send_datagram(bytes) {
        Ok(()) => Ok(true),

        Err(quinn::SendDatagramError::TooLarge)
        | Err(quinn::SendDatagramError::UnsupportedByPeer)
        | Err(quinn::SendDatagramError::Disabled) => Ok(false),

        Err(quinn::SendDatagramError::ConnectionLost(error)) => Err(error),
    }
}

pub(crate) fn tune_udp_buffers(socket: &std::net::UdpSocket) {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;

        let fd = socket.as_raw_fd();

        let size = (8 * 1024 * 1024) as libc::c_int;

        let len = std::mem::size_of_val(&size) as libc::socklen_t;

        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&size as *const libc::c_int).cast(),
                len,
            );

            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&size as *const libc::c_int).cast(),
                len,
            );
        }
    }

    let _ = socket;
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use crate::{
        client::create_client_endpoint,
        identity::{ClientTlsConfig, SERVER_NAME, ServerTlsConfig, ensure_dev_identity},
        obfuscation::ObfuscationKey,
        server::create_server_endpoint,
    };

    #[test]
    fn dev_identity_can_be_created() {
        //
        // Проверяем, что dev certificate
        // и private key могут быть созданы.
        //
        ensure_dev_identity().expect("failed to create PAYPHONE dev identity");
    }

    #[tokio::test]
    async fn server_endpoint_can_bind() {
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        let key = ObfuscationKey::from_passphrase("test-obfuscation-passphrase");

        let endpoint =
            create_server_endpoint(address, key, true, &ServerTlsConfig::default())
                .expect("endpoint creation failed");

        let local_address = endpoint
            .local_addr()
            .expect("failed to get endpoint address");

        assert_ne!(local_address.port(), 0);

        //
        // Корректно закрываем Endpoint.
        //
        endpoint.close(0u32.into(), b"test finished");

        endpoint.wait_idle().await;
    }

    //
    // Полный round-trip через ObfuscatedSocket: сервер и клиент
    // с одинаковым passphrase должны завершить QUIC handshake.
    //
    // Это проверяет реальную логику send/recv/deobfuscate внутри
    // ObfuscatedSocket, а не только то, что endpoint создаётся.
    //
    #[tokio::test]
    async fn handshake_succeeds_through_obfuscated_socket() {
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        let key = ObfuscationKey::from_passphrase("matching-passphrase");

        let server_endpoint =
            create_server_endpoint(address, key.clone(), true, &ServerTlsConfig::default())
                .expect("server endpoint creation failed");

        let server_address = server_endpoint
            .local_addr()
            .expect("failed to get server endpoint address");

        let server_task = tokio::spawn(async move {
            let incoming = server_endpoint
                .accept()
                .await
                .expect("server did not receive a connection attempt");

            incoming.await.expect("server-side handshake failed")
        });

        let client_endpoint = create_client_endpoint(
            key,
            true,
            None,
            None,
            &ClientTlsConfig::default(),
        )
        .expect("client endpoint creation failed");

        let client_connection = client_endpoint
            .connect(server_address, SERVER_NAME)
            .expect("client connect() setup failed")
            .await
            .expect("client-side handshake failed");

        let server_connection = server_task.await.expect("server task panicked");

        assert_eq!(
            client_connection.remote_address().port(),
            server_address.port()
        );

        client_connection.close(0u32.into(), b"test finished");
        server_connection.close(0u32.into(), b"test finished");
    }

    //
    // Клиент и сервер с разными passphrase не должны понимать
    // друг друга на проводе — handshake обязан не завершиться
    // за разумное время.
    //
    #[tokio::test]
    async fn handshake_fails_with_mismatched_passphrase() {
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        let server_key = ObfuscationKey::from_passphrase("server-side-passphrase");

        let client_key = ObfuscationKey::from_passphrase("different-client-passphrase");

        let server_endpoint =
            create_server_endpoint(address, server_key, true, &ServerTlsConfig::default())
                .expect("server endpoint creation failed");

        let server_address = server_endpoint
            .local_addr()
            .expect("failed to get server endpoint address");

        // Сервер не должен увидеть даже попытку подключения:
        // ObfuscatedSocket молча отбрасывает всё, что не
        // деобфусцируется валидным passphrase.
        let server_task = tokio::spawn(async move { server_endpoint.accept().await });

        let client_endpoint = create_client_endpoint(
            client_key,
            true,
            None,
            None,
            &ClientTlsConfig::default(),
        )
        .expect("client endpoint creation failed");

        let client_result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client_endpoint
                .connect(server_address, SERVER_NAME)
                .expect("client connect() setup failed"),
        )
        .await;

        assert!(
            client_result.is_err() || client_result.unwrap().is_err(),
            "handshake unexpectedly succeeded with mismatched obfuscation passphrase"
        );

        server_task.abort();
    }

    //
    // Regression test for a real production failure:
    // SendDatagramError::TooLarge on an otherwise-honest,
    // PAYPHONE_MTU-sized frame sent immediately after the
    // handshake — before QUIC's own MTU discovery has had any
    // chance to grow the datagram budget past its safe RFC 9000
    // floor (1200 bytes, ~1154 usable after quinn's own overhead).
    //
    // MAX_FRAME_SIZE mirrors payphone_tun::PAYPHONE_MTU (1100) +
    // payphone_core::HEADER_SIZE (16) + data::DATA_HEADER_SIZE (24)
    // without pulling in those crates as a dependency here.
    #[tokio::test]
    async fn max_size_frame_sends_immediately_after_handshake() {
        const MAX_FRAME_SIZE: usize = 1100 + 16 + 24;

        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        let key = ObfuscationKey::from_passphrase("matching-passphrase");

        let server_endpoint =
            create_server_endpoint(address, key.clone(), true, &ServerTlsConfig::default())
                .expect("server endpoint creation failed");

        let server_address = server_endpoint
            .local_addr()
            .expect("failed to get server endpoint address");

        let server_task = tokio::spawn(async move {
            let incoming = server_endpoint
                .accept()
                .await
                .expect("server did not receive a connection attempt");

            incoming.await.expect("server-side handshake failed")
        });

        let client_endpoint = create_client_endpoint(
            key,
            true,
            None,
            None,
            &ClientTlsConfig::default(),
        )
        .expect("client endpoint creation failed");

        let client_connection = client_endpoint
            .connect(server_address, SERVER_NAME)
            .expect("client connect() setup failed")
            .await
            .expect("client-side handshake failed");

        let server_connection = server_task.await.expect("server task panicked");

        let payload = vec![0xABu8; MAX_FRAME_SIZE];

        client_connection
            .send_datagram_wait(payload.clone().into())
            .await
            .expect("max-size PAYPHONE frame should fit within quinn's guaranteed MTU floor");

        let received = server_connection
            .read_datagram()
            .await
            .expect("server did not receive the datagram");

        assert_eq!(received.as_ref(), payload.as_slice());

        client_connection.close(0u32.into(), b"test finished");
        server_connection.close(0u32.into(), b"test finished");
    }
}
