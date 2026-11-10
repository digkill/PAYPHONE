use std::{io, sync::Arc};

use tokio::sync::RwLock;

use payphone_core::data::Data;
use payphone_tun::{
    SERVER_TUN_IPV4, SharedTun,
    ipv4::{MtuResult, fit_packet},
    ipv4_destination,
};

use crate::{
    handler::PayphoneVerifier,
    session::{ClientLink, RateLimit, SessionId, SessionManager},
};

/// Keep TUN reads independent of connection setup and session cleanup.
pub async fn run(
    tun: SharedTun,
    sessions: Arc<RwLock<SessionManager>>,
    verifier: Arc<PayphoneVerifier>,
) -> io::Result<()> {
    let mut buffer = vec![0; 65535];
    let mut sequence = 1u64;
    // Bound ICMP generation when a sender ignores path-MTU feedback.
    let icmp_rate = RateLimit::new(1);
    loop {
        let size = tun.recv(&mut buffer).await?;
        let packet = &buffer[..size];
        let Some(destination) = ipv4_destination(packet) else {
            continue;
        };
        let route = {
            let manager = sessions.read().await;
            manager.find_by_ipv4(destination).and_then(|session| {
                if session.access_error(verifier.as_ref()).is_some()
                    || !session.download_rate.allow(size as u64)
                {
                    return None;
                }
                session.record_activity();
                Some((session.id, session.link.clone()))
            })
        };
        let Some((session_id, link)) = route else {
            continue;
        };
        // Let send_datagram validate MTU under the same lock as the enqueue.
        // The normal case needs neither a separate budget lookup nor a retry.
        if send_ip(&link, session_id, &mut sequence, packet).await {
            continue;
        }
        let mtu = link.ip_mtu();
        if mtu < 68 || size <= usize::from(mtu) {
            continue;
        }
        match fit_packet(packet, mtu, SERVER_TUN_IPV4) {
            MtuResult::Fragments(fragments) => {
                for fragment in fragments {
                    send_ip(&link, session_id, &mut sequence, &fragment).await;
                }
            }
            MtuResult::FragmentationNeeded(reply) => {
                if icmp_rate.allow(reply.len() as u64) {
                    tun.send(&reply).await?;
                }
            }
            MtuResult::Drop => {}
        }
    }
}

async fn send_ip(
    link: &ClientLink,
    session_id: SessionId,
    sequence: &mut u64,
    packet: &[u8],
) -> bool {
    let Ok(frame) = Data::encode_frame(session_id, *sequence, *sequence, packet) else {
        return false;
    };
    *sequence = sequence.wrapping_add(1);
    link.send(frame).await
}
