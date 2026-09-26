//! Authorized deployment smoke test, without a local TUN or route changes.
//! Set PAYPHONE_SERVER_ADDR, PAYPHONE_OBFS_PSK, PAYPHONE_TLS_PIN,
//! PAYPHONE_TLS_CA=pin, PAYPHONE_SERVER_NAME=localhost, PAYPHONE_TOKEN.
//! Checks authentication, Rekey, resume, DNS via TUN/NAT and a 1100-byte packet.
use bytes::Bytes;
use payphone_core::{
    Frame, FrameType, PROTOCOL_VERSION,
    all_good_dude::AllGoodDude,
    back_again_dude::BackAgainDude,
    close::{Close, CloseReason},
    data::Data,
    ping::Ping,
    pong::Pong,
    rekey::Rekey,
    whats_up_dude::WhatsUpDude,
};
use payphone_transport::{
    client::create_client_endpoint, https_front::TlsClientSession, identity::ClientTlsConfig,
    obfuscation::ObfuscationKey, send_vpn_datagram,
};
use std::{env, fs, net::SocketAddr, time::Duration};
type Error = Box<dyn std::error::Error>;
enum Link {
    Quic(quinn::Connection),
    Tls(TlsClientSession),
}
impl Link {
    async fn send(&self, kind: FrameType, sequence: u64, payload: Bytes) -> Result<(), Error> {
        let bytes = Frame {
            version: PROTOCOL_VERSION,
            frame_type: kind,
            flags: 0,
            sequence,
            payload,
        }
        .encode();
        match self {
            Self::Quic(c) => {
                send_vpn_datagram(c, bytes)?;
            }
            Self::Tls(c) => c.send_frame_bytes(&bytes).await?,
        }
        Ok(())
    }
    async fn recv(&mut self, expected: FrameType) -> Result<Frame, Error> {
        let frame = tokio::time::timeout(Duration::from_secs(10), async {
            match self {
                Self::Quic(c) => Ok::<_, Error>(Frame::decode(c.read_datagram().await?)?),
                Self::Tls(c) => Ok(c.recv_frame().await?),
            }
        })
        .await??;
        if frame.frame_type != expected {
            return Err(format!("expected {expected:?}, got {:?}", frame.frame_type).into());
        }
        Ok(frame)
    }
}
fn ipv4(src: [u8; 4], dest: [u8; 4], protocol: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 20];
    out[0] = 0x45;
    out[2..4].copy_from_slice(&((20 + body.len()) as u16).to_be_bytes());
    out[8] = 64;
    out[9] = protocol;
    out[12..16].copy_from_slice(&src);
    out[16..20].copy_from_slice(&dest);
    let mut sum: u32 = out
        .chunks_exact(2)
        .map(|w| u16::from_be_bytes([w[0], w[1]]) as u32)
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    out[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    out.extend_from_slice(body);
    out
}
async fn exercise(link: &mut Link, token: Bytes) -> Result<([u8; 16], [u8; 32]), Error> {
    // An unknown resume must answer promptly so mobile clients can re-authenticate.
    link.send(
        FrameType::BackAgainDude,
        1,
        BackAgainDude::new([0; 16], [0; 32]).encode(),
    )
    .await?;
    link.recv(FrameType::AccessDeniedDude).await?;
    link.send(
        FrameType::WhatsUpDude,
        2,
        WhatsUpDude::new(2, 1 | 4 | 8 | 16, token).encode(),
    )
    .await?;
    let session = AllGoodDude::decode(link.recv(FrameType::AllGoodDude).await?.payload)?;
    println!(
        "Authenticated; IPv4={:?}, MTU={}",
        session.assigned_ipv4, session.mtu
    );
    link.send(
        FrameType::Ping,
        3,
        Ping::new(session.session_id, 123).encode(),
    )
    .await?;
    let pong = Pong::decode(link.recv(FrameType::Pong).await?.payload)?;
    assert_eq!(pong.ping_id, 123);
    link.send(
        FrameType::Rekey,
        4,
        Rekey::request(session.session_id).encode(),
    )
    .await?;
    let Rekey::Token { session_id, nonce } =
        Rekey::decode(link.recv(FrameType::Rekey).await?.payload)?
    else {
        return Err("expected Rekey offer".into());
    };
    assert_eq!(session_id, session.session_id);
    link.send(
        FrameType::Rekey,
        5,
        Rekey::token(session_id, nonce).encode(),
    )
    .await?;
    link.recv(FrameType::Rekey).await?;
    // Duplicate ACK must not restart a Rekey echo loop.
    link.send(
        FrameType::Rekey,
        6,
        Rekey::token(session_id, nonce).encode(),
    )
    .await?;
    link.send(FrameType::Ping, 7, Ping::new(session_id, 124).encode())
        .await?;
    link.recv(FrameType::Pong).await?;
    for (i, dest) in [[10, 77, 0, 1], [1, 1, 1, 1]].into_iter().enumerate() {
        let dns=b"\x51\x29\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
        let mut udp = vec![];
        udp.extend_from_slice(&53001u16.to_be_bytes());
        udp.extend_from_slice(&53u16.to_be_bytes());
        udp.extend_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&[0, 0]);
        udp.extend_from_slice(dns);
        let packet = ipv4(session.assigned_ipv4, dest, 17, &udp);
        link.send(
            FrameType::Data,
            8 + i as u64,
            Data::new(session_id, 1 + i as u64, packet.into()).encode(),
        )
        .await?;
        let data = Data::decode(link.recv(FrameType::Data).await?.payload)?;
        assert_eq!(data.session_id, session_id);
        let ip = &data.payload;
        let offset = ((ip[0] & 15) as usize) * 4 + 8;
        assert_eq!(&ip[12..16], &dest);
        assert_eq!(&ip[16..20], &session.assigned_ipv4);
        assert_eq!(&ip[offset..offset + 2], &dns[..2]);
        assert_ne!(ip[offset + 2] & 0x80, 0);
        assert_eq!(ip[offset + 3] & 15, 0);
        println!("DNS roundtrip via {dest:?}: OK");
    }
    let packet = ipv4(session.assigned_ipv4, [1, 1, 1, 1], 253, &vec![0; 1080]);
    link.send(
        FrameType::Data,
        10,
        Data::new(session_id, 3, packet.into()).encode(),
    )
    .await?;
    println!("1100-byte inner IPv4 packet sent: OK");
    Ok((session_id, nonce))
}
#[tokio::main]
async fn main() -> Result<(), Error> {
    let address: SocketAddr = env::var("PAYPHONE_SERVER_ADDR")?.parse()?;
    let tls = ClientTlsConfig::from_env();
    let token = Bytes::from(fs::read(env::var("PAYPHONE_TOKEN")?)?);
    let endpoint = create_client_endpoint(
        ObfuscationKey::from_passphrase(&env::var("PAYPHONE_OBFS_PSK")?),
        false,
        None,
        None,
        &tls,
    )?;
    for protocol in ["quic", "tls"] {
        println!("Testing {protocol} on {address}");
        let mut link = if protocol == "quic" {
            Link::Quic(
                tokio::time::timeout(
                    Duration::from_secs(15),
                    endpoint.connect(address, &tls.server_name)?,
                )
                .await??,
            )
        } else {
            Link::Tls(TlsClientSession::connect(address, &tls).await?)
        };
        let (id, nonce) = exercise(&mut link, token.clone()).await?;
        if let Link::Quic(c) = &link {
            c.close(0u32.into(), b"resume probe");
        }
        drop(link);
        // Resume over a new TLS connection also checks migration across transports.
        let mut resumed = Link::Tls(TlsClientSession::connect(address, &tls).await?);
        resumed
            .send(
                FrameType::BackAgainDude,
                1,
                BackAgainDude::new(id, nonce).encode(),
            )
            .await?;
        resumed.recv(FrameType::StillGoodDude).await?;
        resumed
            .send(
                FrameType::Close,
                2,
                Close::new(id, CloseReason::ClientShutdown).encode(),
            )
            .await?;
        println!("Resume on fresh connection: OK");
    }
    endpoint.close(0u32.into(), b"probe done");
    Ok(())
}
