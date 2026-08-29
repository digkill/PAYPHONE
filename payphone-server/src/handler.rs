use std::{
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;

use tokio::sync::RwLock;

use payphone_auth::{AuthError, MemoryRevocationStore, SubscriptionToken, SubscriptionVerifier};

use payphone_core::{
    Frame, FrameType, PROTOCOL_VERSION,
    access_denied_dude::{AccessDeniedDude, DenyReason},
    back_again_dude::BackAgainDude,
    close::{Close, CloseReason},
    data::Data,
    ping::Ping,
    pong::Pong,
    rekey::Rekey,
    whats_up_dude::{CAP_DNS, CAP_IPV4, CAP_RESUME, WhatsUpDude},
};

use payphone_tun::{PAYPHONE_MTU, SharedTun, ipv4_source};

use crate::session::{ClientLink, CreateSessionError, SessionManager};

const SERVER_CAPABILITIES: u32 = CAP_IPV4 | CAP_DNS | CAP_RESUME;

pub type PayphoneVerifier = SubscriptionVerifier<MemoryRevocationStore>;

pub async fn handle_frame(
    link: ClientLink,

    client_address: SocketAddr,

    sessions: Arc<RwLock<SessionManager>>,

    verifier: Arc<PayphoneVerifier>,

    tun: SharedTun,

    frame: Frame,
) {
    match frame.frame_type {
        FrameType::WhatsUpDude => {
            handle_whats_up_dude(link, sessions, verifier, client_address, frame).await;
        }

        FrameType::BackAgainDude => {
            handle_back_again_dude(link, sessions, client_address, frame).await;
        }

        FrameType::Data => {
            handle_data(sessions, tun, client_address, frame).await;
        }

        FrameType::Ping => {
            handle_ping(link, sessions, client_address, frame).await;
        }

        FrameType::Pong
        | FrameType::AllGoodDude
        | FrameType::StillGoodDude
        | FrameType::AccessDeniedDude => {}

        FrameType::Rekey => {
            handle_rekey(link, sessions, client_address, frame).await;
        }

        FrameType::Close => {
            handle_close(link, sessions, client_address, frame).await;
        }
    }
}

pub async fn handle_packet(
    connection: quinn::Connection,

    sessions: Arc<RwLock<SessionManager>>,

    verifier: Arc<PayphoneVerifier>,

    tun: SharedTun,

    packet: Bytes,
) {
    let client_address = connection.remote_address();

    let frame = match Frame::decode(packet) {
        Ok(frame) => frame,

        Err(error) => {
            eprintln!("Invalid PAYPHONE frame: {}", error);

            return;
        }
    };

    handle_frame(
        ClientLink::Quic(connection),
        client_address,
        sessions,
        verifier,
        tun,
        frame,
    )
    .await;
}

async fn handle_whats_up_dude(
    link: ClientLink,

    sessions: Arc<RwLock<SessionManager>>,

    verifier: Arc<PayphoneVerifier>,

    client_address: SocketAddr,

    frame: Frame,
) {
    let sequence = frame.sequence;

    let whats_up = match WhatsUpDude::decode(frame.payload) {
        Ok(value) => value,

        Err(error) => {
            eprintln!("Invalid WhatsUpDude: {}", error);

            return;
        }
    };

    let token = match SubscriptionToken::decode(whats_up.auth_token) {
        Ok(token) => token,

        Err(_) => {
            send_access_denied(&link, sequence, DenyReason::InvalidToken, 0).await;

            return;
        }
    };

    let claims = match verifier.verify(&token) {
        Ok(claims) => claims,

        Err(error) => {
            let (reason, expires_at) = auth_error_to_deny(&error, token.claims.expires_at);

            send_access_denied(&link, sequence, reason, expires_at).await;

            return;
        }
    };

    println!("Subscription accepted: {:?}", claims.plan);

    let capabilities = whats_up.capabilities & SERVER_CAPABILITIES;

    let created = {
        let mut manager = sessions.write().await;

        manager.create_session(
            client_address,
            link.clone(),
            capabilities,
            whats_up.client_nonce,
            sequence,
            PAYPHONE_MTU,
            &claims,
        )
    };

    let (all_good, kicked) = match created {
        Ok(value) => value,

        Err(CreateSessionError::NoAddresses) => {
            send_access_denied(&link, sequence, DenyReason::InternalAuthError, 0).await;

            return;
        }
    };

    for kicked in kicked {
        send_close(&kicked.link, kicked.id, CloseReason::Replaced).await;

        println!("Kicked session {:02x?} (device limit)", kicked.id);
    }

    let response = Frame {
        version: PROTOCOL_VERSION,

        frame_type: FrameType::AllGoodDude,

        flags: 0,

        sequence: sequence + 1,

        payload: all_good.encode(),
    };

    link.send(response.encode()).await;

    println!(
        "Session {}.{}.{}.{} created",
        all_good.assigned_ipv4[0],
        all_good.assigned_ipv4[1],
        all_good.assigned_ipv4[2],
        all_good.assigned_ipv4[3],
    );
}

async fn handle_back_again_dude(
    link: ClientLink,

    sessions: Arc<RwLock<SessionManager>>,

    client_address: SocketAddr,

    frame: Frame,
) {
    let sequence = frame.sequence;

    let message = match BackAgainDude::decode(frame.payload) {
        Ok(message) => message,

        Err(_) => return,
    };

    let expired = {
        let manager = sessions.read().await;

        match manager.get(&message.session_id) {
            Some(session) => unix_time() >= session.subscription_expires_at,

            None => false,
        }
    };

    if expired {
        send_access_denied(&link, sequence, DenyReason::SubscriptionExpired, 0).await;

        return;
    }

    let resumed = {
        let mut manager = sessions.write().await;

        manager.resume_session(
            &message.session_id,
            &message.resume_token,
            client_address,
            link.clone(),
            sequence,
            PAYPHONE_MTU,
        )
    };

    let Some(still_good) = resumed else {
        return;
    };

    let response = Frame {
        version: PROTOCOL_VERSION,

        frame_type: FrameType::StillGoodDude,

        flags: 0,

        sequence: sequence + 1,

        payload: still_good.encode(),
    };

    link.send(response.encode()).await;
}

async fn handle_data(
    sessions: Arc<RwLock<SessionManager>>,

    tun: SharedTun,

    client_address: SocketAddr,

    frame: Frame,
) {
    let data = match Data::decode(frame.payload) {
        Ok(data) => data,

        Err(error) => {
            eprintln!("Invalid DATA: {}", error);

            return;
        }
    };

    let allowed = {
        let manager = sessions.read().await;

        let Some(session) = manager.get(&data.session_id) else {
            return;
        };

        if session.client_address != client_address {
            return;
        }

        if unix_time() >= session.subscription_expires_at {
            return;
        }

        if !session.rate.allow(data.payload.len() as u64) {
            return;
        }

        if let Some(source) = ipv4_source(&data.payload) {
            if source != session.ipv4 {
                eprintln!("Spoofed VPN source address");

                return;
            }
        }

        true
    };

    if !allowed {
        return;
    }

    if let Err(error) = tun.send(&data.payload).await {
        eprintln!("TUN write error: {}", error);
    }
}

async fn handle_ping(
    link: ClientLink,

    sessions: Arc<RwLock<SessionManager>>,

    client_address: SocketAddr,

    frame: Frame,
) {
    let sequence = frame.sequence;

    let ping = match Ping::decode(frame.payload) {
        Ok(ping) => ping,

        Err(_) => return,
    };

    let rekey_nonce = {
        let mut manager = sessions.write().await;

        manager.touch_session(&ping.session_id, client_address, sequence)
    };

    let Some(rekey_nonce) = rekey_nonce else {
        return;
    };

    let pong = Pong::new(ping.session_id, ping.ping_id);

    let frame = Frame {
        version: PROTOCOL_VERSION,

        frame_type: FrameType::Pong,

        flags: 0,

        sequence: sequence + 1,

        payload: pong.encode(),
    };

    link.send(frame.encode()).await;

    if let Some(nonce) = rekey_nonce {
        send_rekey(&link, ping.session_id, nonce).await;
    }
}

async fn send_access_denied(
    link: &ClientLink,

    sequence: u64,

    reason: DenyReason,

    expires_at: u64,
) {
    let denied = AccessDeniedDude::new(reason, expires_at);

    let frame = Frame {
        version: PROTOCOL_VERSION,

        frame_type: FrameType::AccessDeniedDude,

        flags: 0,

        sequence: sequence + 1,

        payload: denied.encode(),
    };

    link.send(frame.encode()).await;
}

async fn handle_rekey(
    link: ClientLink,

    sessions: Arc<RwLock<SessionManager>>,

    client_address: SocketAddr,

    frame: Frame,
) {
    let rekey = match Rekey::decode(frame.payload) {
        Ok(rekey) => rekey,

        Err(_) => return,
    };

    let session_id = rekey.session_id();

    let nonce = {
        let mut manager = sessions.write().await;

        match rekey {
            Rekey::Request { .. } => manager.rekey_offer(&session_id, client_address),

            Rekey::Token { nonce, .. } => {
                manager.rekey_confirm(&session_id, &nonce, client_address)
            }
        }
    };

    let Some(nonce) = nonce else {
        return;
    };

    send_rekey(&link, session_id, nonce).await;
}

async fn handle_close(
    link: ClientLink,

    sessions: Arc<RwLock<SessionManager>>,

    client_address: SocketAddr,

    frame: Frame,
) {
    let close = match Close::decode(frame.payload) {
        Ok(close) => close,

        Err(_) => return,
    };

    let removed = {
        let mut manager = sessions.write().await;

        let matches = manager
            .get(&close.session_id)
            .is_some_and(|session| session.client_address == client_address);

        if matches {
            manager.remove(&close.session_id);

            true
        } else {
            false
        }
    };

    if !removed {
        return;
    }

    send_close(&link, close.session_id, close.reason).await;

    println!("Session {:02x?} closed ({:?})", close.session_id, close.reason);
}

async fn send_close(link: &ClientLink, session_id: [u8; 16], reason: CloseReason) {
    let close = Close::new(session_id, reason);

    let frame = Frame {
        version: PROTOCOL_VERSION,

        frame_type: FrameType::Close,

        flags: 0,

        sequence: 0,

        payload: close.encode(),
    };

    link.send(frame.encode()).await;
}

async fn send_rekey(link: &ClientLink, session_id: [u8; 16], nonce: [u8; 32]) {
    let rekey = Rekey::token(session_id, nonce);

    let frame = Frame {
        version: PROTOCOL_VERSION,

        frame_type: FrameType::Rekey,

        flags: 0,

        sequence: 0,

        payload: rekey.encode(),
    };

    link.send(frame.encode()).await;
}

fn auth_error_to_deny(error: &AuthError, expires_at: u64) -> (DenyReason, u64) {
    match error {
        AuthError::Expired => (DenyReason::SubscriptionExpired, expires_at),

        AuthError::Revoked => (DenyReason::TokenRevoked, 0),

        AuthError::NotYetValid => (DenyReason::SubscriptionNotActive, 0),

        AuthError::UnknownKeyId(_) => (DenyReason::UnknownSigningKey, 0),

        AuthError::UnknownPlan(_) => (DenyReason::UnsupportedPlan, 0),

        _ => (DenyReason::InvalidToken, 0),
    }
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
