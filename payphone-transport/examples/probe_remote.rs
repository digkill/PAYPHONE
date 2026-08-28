// One-off manual probe against a REAL deployed PAYPHONE server —
// not part of the test suite (that stays on loopback). Confirms
// the actual production path (not just in-process loopback)
// handles a PAYPHONE_MTU-sized datagram right after handshake.
//
// Usage: PAYPHONE_SERVER_ADDR=host:port PAYPHONE_OBFS_PSK=... cargo run -p payphone-transport --example probe_remote

use std::{env, net::ToSocketAddrs};

use payphone_transport::{client::create_client_endpoint, identity::SERVER_NAME, obfuscation::ObfuscationKey};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_addr = env::var("PAYPHONE_SERVER_ADDR")?;
    let server_address = server_addr.to_socket_addrs()?.next().ok_or("no address resolved")?;

    let psk = env::var("PAYPHONE_OBFS_PSK")?;
    let key = ObfuscationKey::from_passphrase(&psk);

    println!("connecting to {server_address} ...");

    let endpoint = create_client_endpoint(key, false)?;

    let connecting = endpoint.connect(server_address, SERVER_NAME)?;

    let connection = match tokio::time::timeout(std::time::Duration::from_secs(15), connecting).await {
        Ok(Ok(connection)) => connection,
        Ok(Err(error)) => {
            println!("connect() resolved with an error: {error}");
            return Err(error.into());
        }
        Err(_) => {
            println!("connect() timed out after 15s waiting for handshake completion");
            return Err("timed out".into());
        }
    };

    println!("QUIC + TLS 1.3 connected, remote={}", connection.remote_address());

    const MAX_FRAME_SIZE: usize = 1100 + 16 + 24;
    let payload = vec![0xABu8; MAX_FRAME_SIZE];

    println!("sending {MAX_FRAME_SIZE}-byte max-size PAYPHONE frame as a raw QUIC datagram...");
    connection.send_datagram_wait(payload.into()).await?;
    println!("OK: max-size datagram sent without TooLarge");

    connection.close(0u32.into(), b"probe done");
    endpoint.wait_idle().await;
    Ok(())
}
