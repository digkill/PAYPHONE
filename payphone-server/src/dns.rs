use std::{net::SocketAddr, sync::Arc, time::Duration};

use tokio::{net::UdpSocket, time::timeout};

use payphone_tun::SERVER_TUN_IPV4;

const QUERY_TIMEOUT: Duration = Duration::from_secs(2);

const MAX_DNS_MESSAGE: usize = 4096;

pub fn default_upstream() -> SocketAddr {
    SocketAddr::from(([1, 1, 1, 1], 53))
}

pub fn fallback_upstream() -> SocketAddr {
    SocketAddr::from(([8, 8, 8, 8], 53))
}

/// UDP DNS stub on the VPN address. Clients pin this as their only
/// resolver so a dropped tunnel cannot fall back to ISP DNS (unlike
/// pinning 1.1.1.1, which is a public address).
pub async fn run(upstream: SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bind = SocketAddr::from((SERVER_TUN_IPV4, 53));

    let socket = bind_with_retry(bind).await?;

    println!("PAYPHONE DNS stub: {bind} → {upstream}");

    let socket = Arc::new(socket);

    let mut buf = vec![0u8; MAX_DNS_MESSAGE];

    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;

        if !looks_like_query(&buf[..len]) {
            continue;
        }

        let query = buf[..len].to_vec();

        let socket = Arc::clone(&socket);

        tokio::spawn(async move {
            if let Some(response) = forward(&query, upstream).await {
                let _ = socket.send_to(&response, peer).await;
            }
        });
    }
}

async fn bind_with_retry(bind: SocketAddr) -> std::io::Result<UdpSocket> {
    let mut last = None;

    for _ in 0..8 {
        match UdpSocket::bind(bind).await {
            Ok(socket) => return Ok(socket),

            Err(error) => {
                last = Some(error);

                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }

    Err(last.unwrap_or_else(|| std::io::Error::other("DNS bind failed")))
}

async fn forward(query: &[u8], primary: SocketAddr) -> Option<Vec<u8>> {
    if let Some(response) = query_upstream(query, primary).await {
        return Some(response);
    }

    query_upstream(query, fallback_upstream()).await
}

async fn query_upstream(query: &[u8], upstream: SocketAddr) -> Option<Vec<u8>> {
    let outbound = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
        .await
        .ok()?;

    outbound.send_to(query, upstream).await.ok()?;

    let mut buf = vec![0u8; MAX_DNS_MESSAGE];

    let (len, _) = timeout(QUERY_TIMEOUT, outbound.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;

    if len < 12 {
        return None;
    }

    Some(buf[..len].to_vec())
}

/// DNS header is 12 bytes. QR (response bit) must be 0 for a query.
pub fn looks_like_query(message: &[u8]) -> bool {
    message.len() >= 12 && message.len() <= MAX_DNS_MESSAGE && message[2] & 0x80 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_too_short() {
        assert!(!looks_like_query(&[0; 8]));
    }

    #[test]
    fn accepts_query_header() {
        let mut query = [0u8; 12];

        query[2] = 0x01;

        assert!(looks_like_query(&query));
    }

    #[test]
    fn rejects_response_header() {
        let mut response = [0u8; 12];

        response[2] = 0x80;

        assert!(!looks_like_query(&response));
    }
}
