use std::{net::SocketAddr, sync::Arc, time::Instant};

use bytes::Bytes;
use quinn::Connection;

use tokio::sync::RwLock;

use payphone_core::{
    Frame, FrameType, PROTOCOL_VERSION,
    back_again_dude::BackAgainDude,
    data::Data,
    ping::Ping,
    pong::Pong,
    whats_up_dude::{CAP_DNS, CAP_IPV4, CAP_RESUME, WhatsUpDude},
};

use crate::session::SessionManager;

//
// Возможности PAYPHONE server.
//
const SERVER_CAPABILITIES: u32 = CAP_IPV4 | CAP_DNS | CAP_RESUME;

//
// MTU виртуального PAYPHONE tunnel.
//
const PAYPHONE_MTU: u16 = 1280;

/// Обрабатывает один PAYPHONE Frame,
/// пришедший внутри QUIC DATAGRAM.
pub async fn handle_packet(
    connection: Connection,

    sessions: Arc<RwLock<SessionManager>>,

    client_address: SocketAddr,

    packet: Bytes,
) {
    //
    // QUIC уже:
    //
    // получил UDP
    // обработал QUIC
    // расшифровал TLS 1.3
    //
    // Здесь уже лежат обычные
    // PAYPHONE bytes.
    //
    let frame = match Frame::decode(packet) {
        Ok(frame) => frame,

        Err(error) => {
            println!("Invalid PAYPHONE frame from {}: {}", client_address, error);

            return;
        }
    };

    println!();
    println!("PAYPHONE frame from {}", client_address);

    println!("  type: {:?}", frame.frame_type);

    println!("  sequence: {}", frame.sequence);

    match frame.frame_type {
        //
        // Новый handshake.
        //
        FrameType::WhatsUpDude => {
            handle_whats_up_dude(connection, sessions, client_address, frame).await;
        }

        //
        // Resume старой Session.
        //
        FrameType::BackAgainDude => {
            handle_back_again_dude(connection, sessions, client_address, frame).await;
        }

        //
        // Пользовательские данные.
        //
        FrameType::Data => {
            handle_data(connection, sessions, client_address, frame).await;
        }

        //
        // Keepalive.
        //
        FrameType::Ping => {
            handle_ping(connection, sessions, client_address, frame).await;
        }

        //
        // Клиент не должен слать PONG
        // в текущей модели.
        //
        FrameType::Pong => {
            println!("Unexpected PONG from client");
        }

        //
        // Это серверные ответы.
        //
        FrameType::AllGoodDude => {
            println!("Unexpected AllGoodDude from client");
        }

        FrameType::StillGoodDude => {
            println!("Unexpected StillGoodDude from client");
        }

        FrameType::Rekey => {
            println!("REKEY not implemented yet");
        }

        FrameType::Close => {
            println!("CLOSE not implemented yet");
        }
    }
}

// =============================================================
// WhatsUpDude
// =============================================================

async fn handle_whats_up_dude(
    connection: Connection,

    sessions: Arc<RwLock<SessionManager>>,

    client_address: SocketAddr,

    frame: Frame,
) {
    let sequence = frame.sequence;

    let whats_up = match WhatsUpDude::decode(frame.payload) {
        Ok(message) => message,

        Err(error) => {
            println!("Invalid WhatsUpDude: {}", error);

            return;
        }
    };

    println!("What's up, dude?");

    println!("  client version: {}", whats_up.client_version);

    println!("  client capabilities: {}", whats_up.capabilities);

    //
    // Оставляем только возможности,
    // которые поддерживают обе стороны.
    //
    let negotiated_capabilities = whats_up.capabilities & SERVER_CAPABILITIES;

    //
    // Создание Session изменяет
    // SessionManager.
    //
    // Поэтому нужен write lock.
    //
    let all_good = {
        let mut sessions = sessions.write().await;

        sessions.create_session(
            client_address,
            negotiated_capabilities,
            whats_up.client_nonce,
            sequence,
            PAYPHONE_MTU,
        )
    };

    //
    // Lock здесь уже отпущен.
    //

    let response = Frame {
        version: PROTOCOL_VERSION,

        frame_type: FrameType::AllGoodDude,

        flags: 0,

        sequence: sequence + 1,

        payload: all_good.encode(),
    };

    //
    // PAYPHONE Frame
    //
    // ->
    //
    // QUIC DATAGRAM.
    //
    if let Err(error) = connection.send_datagram_wait(response.encode()).await {
        println!("AllGoodDude send error: {}", error);

        return;
    }

    print!("Created Session ID: ");

    for byte in all_good.session_id {
        print!("{:02x}", byte);
    }

    println!();

    println!(
        "Assigned IPv4: {}.{}.{}.{}",
        all_good.assigned_ipv4[0],
        all_good.assigned_ipv4[1],
        all_good.assigned_ipv4[2],
        all_good.assigned_ipv4[3],
    );

    println!("All good, dude.");
}

// =============================================================
// BackAgainDude
// =============================================================

async fn handle_back_again_dude(
    connection: Connection,

    sessions: Arc<RwLock<SessionManager>>,

    client_address: SocketAddr,

    frame: Frame,
) {
    let sequence = frame.sequence;

    let back_again = match BackAgainDude::decode(frame.payload) {
        Ok(message) => message,

        Err(error) => {
            println!("Invalid BackAgainDude: {}", error);

            return;
        }
    };

    println!("Back again, dude?");

    //
    // Resume изменяет:
    //
    // client_address
    // last_sequence
    // last_activity
    //
    let still_good = {
        let mut sessions = sessions.write().await;

        sessions.resume_session(
            &back_again.session_id,
            &back_again.resume_token,
            client_address,
            sequence,
            PAYPHONE_MTU,
        )
    };

    let still_good = match still_good {
        Some(session) => session,

        None => {
            println!("Session resume rejected");

            return;
        }
    };

    println!("Session resumed");

    println!(
        "  IPv4: {}.{}.{}.{}",
        still_good.assigned_ipv4[0],
        still_good.assigned_ipv4[1],
        still_good.assigned_ipv4[2],
        still_good.assigned_ipv4[3],
    );

    let response = Frame {
        version: PROTOCOL_VERSION,

        frame_type: FrameType::StillGoodDude,

        flags: 0,

        sequence: sequence + 1,

        payload: still_good.encode(),
    };

    if let Err(error) = connection.send_datagram_wait(response.encode()).await {
        println!("StillGoodDude send error: {}", error);

        return;
    }

    println!("Still good, dude.");
}

// =============================================================
// DATA
// =============================================================

async fn handle_data(
    connection: Connection,

    sessions: Arc<RwLock<SessionManager>>,

    client_address: SocketAddr,

    frame: Frame,
) {
    let frame_sequence = frame.sequence;

    let data = match Data::decode(frame.payload) {
        Ok(data) => data,

        Err(error) => {
            println!("Invalid DATA: {}", error);

            return;
        }
    };

    //
    // Обновляем Session.
    //
    {
        let mut sessions = sessions.write().await;

        let session = match sessions.get_mut(&data.session_id) {
            Some(session) => session,

            None => {
                println!("Unknown DATA Session");

                return;
            }
        };

        //
        // Resume уже умеет менять endpoint.
        //
        // После успешного Resume здесь
        // должен быть текущий QUIC peer.
        //
        if session.client_address != client_address {
            println!("DATA client address mismatch");

            return;
        }

        session.last_activity = Instant::now();

        session.last_sequence = frame_sequence;

        println!(
            "DATA from {}.{}.{}.{}",
            session.ipv4[0], session.ipv4[1], session.ipv4[2], session.ipv4[3],
        );
    }

    //
    // Write lock уже отпущен.
    //

    println!("DATA packet ID: {}", data.packet_id);

    //
    // Сейчас payload тестовый текст.
    //
    // На этапе TUN здесь будут
    // бинарные IPv4/IPv6 packets.
    //
    let text = String::from_utf8_lossy(&data.payload);

    println!("Payload: {}", text);

    //
    // Тестовый ответ сервера.
    //
    let response_data = Data::new(
        data.session_id,
        1,
        Bytes::from_static(b"Loud and clear, dude."),
    );

    let response_frame = Frame {
        version: PROTOCOL_VERSION,

        frame_type: FrameType::Data,

        flags: 0,

        sequence: frame_sequence + 1,

        payload: response_data.encode(),
    };

    if let Err(error) = connection.send_datagram_wait(response_frame.encode()).await {
        println!("DATA response error: {}", error);

        return;
    }

    println!("DATA response sent");
}

// =============================================================
// PING
// =============================================================

async fn handle_ping(
    connection: Connection,

    sessions: Arc<RwLock<SessionManager>>,

    client_address: SocketAddr,

    frame: Frame,
) {
    let frame_sequence = frame.sequence;

    let ping = match Ping::decode(frame.payload) {
        Ok(ping) => ping,

        Err(error) => {
            println!("Invalid PING: {}", error);

            return;
        }
    };

    {
        let mut sessions = sessions.write().await;

        let session = match sessions.get_mut(&ping.session_id) {
            Some(session) => session,

            None => {
                println!("PING for unknown Session");

                return;
            }
        };

        if session.client_address != client_address {
            println!("PING client address mismatch");

            return;
        }

        session.last_activity = Instant::now();

        session.last_sequence = frame_sequence;
    }

    println!("PING received");

    println!("  ping ID: {}", ping.ping_id);

    //
    // Ответ имеет тот же ping_id.
    //
    let pong = Pong::new(ping.session_id, ping.ping_id);

    let pong_frame = Frame {
        version: PROTOCOL_VERSION,

        frame_type: FrameType::Pong,

        flags: 0,

        sequence: frame_sequence + 1,

        payload: pong.encode(),
    };

    if let Err(error) = connection.send_datagram_wait(pong_frame.encode()).await {
        println!("PONG send error: {}", error);

        return;
    }

    println!("PONG sent");
}
