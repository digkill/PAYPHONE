pub mod client;
pub mod identity;
pub mod server;

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use crate::{identity::ensure_dev_identity, server::create_server_endpoint};

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

        let endpoint = create_server_endpoint(address).expect("endpoint creation failed");

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
}
