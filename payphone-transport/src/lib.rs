pub mod client;
pub mod identity;
pub mod obfuscated_socket;
pub mod obfuscation;
pub mod server;

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use crate::{
        client::create_client_endpoint,
        identity::{SERVER_NAME, ensure_dev_identity},
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
            create_server_endpoint(address, key, true).expect("endpoint creation failed");

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

        let server_endpoint = create_server_endpoint(address, key.clone(), true)
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

        let client_endpoint =
            create_client_endpoint(key, true).expect("client endpoint creation failed");

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

        let server_endpoint = create_server_endpoint(address, server_key, true)
            .expect("server endpoint creation failed");

        let server_address = server_endpoint
            .local_addr()
            .expect("failed to get server endpoint address");

        // Сервер не должен увидеть даже попытку подключения:
        // ObfuscatedSocket молча отбрасывает всё, что не
        // деобфусцируется валидным passphrase.
        let server_task = tokio::spawn(async move { server_endpoint.accept().await });

        let client_endpoint =
            create_client_endpoint(client_key, true).expect("client endpoint creation failed");

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

        let server_endpoint = create_server_endpoint(address, key.clone(), true)
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

        let client_endpoint =
            create_client_endpoint(key, true).expect("client endpoint creation failed");

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
