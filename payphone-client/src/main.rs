use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    time::Duration,
};

use bytes::Bytes;

use quinn::Connection;

use tokio::time;

use payphone_core::{
    DEFAULT_PORT, Frame, FrameType, PROTOCOL_VERSION,
    all_good_dude::{AllGoodDude, SERVER_NONCE_SIZE, SESSION_ID_SIZE},
    back_again_dude::BackAgainDude,
    data::Data,
    ping::Ping,
    pong::Pong,
    still_good_dude::StillGoodDude,
    whats_up_dude::{CAP_DNS, CAP_IPV4, CAP_IPV6, CAP_RESUME, CAP_ROAMING, WhatsUpDude},
};

use payphone_transport::{client::create_client_endpoint, identity::SERVER_NAME};

//
// Версия PAYPHONE client application.
//
// Это НЕ версия wire protocol.
//
const CLIENT_VERSION: u16 = 1;

//
// Возможности клиента.
//
const CLIENT_CAPABILITIES: u32 = CAP_IPV4 | CAP_IPV6 | CAP_DNS | CAP_RESUME | CAP_ROAMING;

//
// Максимальное время ожидания
// ответа сервера.
//
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

//
// Здесь временно сохраняем:
//
// Session ID
// +
// Resume Token
//
// Позже сделаем нормальный
// persistent client state.
//
const SESSION_FILE: &str = ".payphone-session";

//
// Сохранённая информация,
// необходимая для Session Resume.
//
struct SavedSession {
    //
    // Какая Session.
    //
    session_id: [u8; SESSION_ID_SIZE],

    //
    // Секрет для подтверждения,
    // что Session действительно наша.
    //
    resume_token: [u8; SERVER_NONCE_SIZE],
}

//
// Унифицированное состояние
// активной PAYPHONE Session.
//
// Неважно:
//
// Session только что создана
//
// или
//
// Session была восстановлена.
//
// Дальше DATA/PING используют
// одинаковую структуру.
//
struct ActiveSession {
    session_id: [u8; SESSION_ID_SIZE],

    assigned_ipv4: [u8; 4],

    mtu: u16,

    capabilities: u32,
}

// =============================================================
// SAVE SESSION
// =============================================================

fn save_session(
    session_id: [u8; SESSION_ID_SIZE],

    resume_token: [u8; SERVER_NONCE_SIZE],
) -> std::io::Result<()> {
    //
    // Размер:
    //
    // 16 + 32 = 48 bytes.
    //
    let mut data = Vec::with_capacity(SESSION_ID_SIZE + SERVER_NONCE_SIZE);

    data.extend_from_slice(&session_id);

    data.extend_from_slice(&resume_token);

    fs::write(SESSION_FILE, data)
}

// =============================================================
// LOAD SESSION
// =============================================================

fn load_session() -> Option<SavedSession> {
    //
    // fs::read возвращает:
    //
    // Result<Vec<u8>, io::Error>
    //
    // .ok()
    //
    // превращает:
    //
    // Ok(data) -> Some(data)
    //
    // Err      -> None
    //
    // ?
    //
    // если None,
    // сразу возвращает None.
    //
    let data = fs::read(SESSION_FILE).ok()?;

    //
    // Файл обязан быть
    // ровно 48 bytes.
    //
    if data.len() != SESSION_ID_SIZE + SERVER_NONCE_SIZE {
        return None;
    }

    let mut session_id = [0u8; SESSION_ID_SIZE];

    //
    // Первые 16 bytes.
    //
    session_id.copy_from_slice(&data[..SESSION_ID_SIZE]);

    let mut resume_token = [0u8; SERVER_NONCE_SIZE];

    //
    // Остальные 32 bytes.
    //
    resume_token.copy_from_slice(&data[SESSION_ID_SIZE..]);

    Some(SavedSession {
        session_id,
        resume_token,
    })
}

// =============================================================
// RECEIVE QUIC DATAGRAM WITH TIMEOUT
// =============================================================

async fn receive_frame(connection: &Connection) -> Result<Frame, Box<dyn std::error::Error>> {
    //
    // Ждём QUIC datagram,
    // но максимум RESPONSE_TIMEOUT.
    //
    let bytes = time::timeout(RESPONSE_TIMEOUT, connection.read_datagram()).await??;

    //
    // QUIC уже:
    //
    // принял UDP
    // расшифровал TLS
    // обработал QUIC
    //
    // Теперь у нас обычные
    // PAYPHONE bytes.
    //
    let frame = Frame::decode(bytes)?;

    Ok(frame)
}

// =============================================================
// TRY SESSION RESUME
// =============================================================

async fn try_resume(
    connection: &Connection,

    saved: SavedSession,
) -> Result<Option<ActiveSession>, Box<dyn std::error::Error>> {
    println!();
    println!("Saved PAYPHONE Session found");

    print!("Session ID: ");

    for byte in saved.session_id {
        print!("{:02x}", byte);
    }

    println!();

    //
    // Создаём:
    //
    // BackAgainDude {
    //     session_id,
    //     resume_token
    // }
    //
    let back_again = BackAgainDude::new(saved.session_id, saved.resume_token);

    let frame = Frame {
        version: PROTOCOL_VERSION,

        frame_type: FrameType::BackAgainDude,

        flags: 0,

        sequence: 1,

        payload: back_again.encode(),
    };

    println!("Back again, dude?");

    //
    // PAYPHONE Frame
    //
    // ->
    //
    // QUIC DATAGRAM.
    //
    connection.send_datagram_wait(frame.encode()).await?;

    //
    // Сервер может:
    //
    // ответить StillGoodDude
    //
    // или
    //
    // вообще не подтвердить resume.
    //
    let response = match time::timeout(Duration::from_secs(2), connection.read_datagram()).await {
        Ok(Ok(bytes)) => bytes,

        //
        // Timeout
        // или ошибка QUIC.
        //
        _ => {
            return Ok(None);
        }
    };

    let frame = match Frame::decode(response) {
        Ok(frame) => frame,

        Err(_) => {
            return Ok(None);
        }
    };

    //
    // Нас интересует только:
    //
    // StillGoodDude.
    //
    if frame.frame_type != FrameType::StillGoodDude {
        return Ok(None);
    }

    let still_good = StillGoodDude::decode(frame.payload)?;

    //
    // Сервер обязан подтвердить
    // именно ту Session,
    // которую мы пытались восстановить.
    //
    if still_good.session_id != saved.session_id {
        return Ok(None);
    }

    println!("Still good, dude.");

    Ok(Some(ActiveSession {
        session_id: still_good.session_id,

        assigned_ipv4: still_good.assigned_ipv4,

        mtu: still_good.mtu,

        capabilities: still_good.capabilities,
    }))
}

// =============================================================
// CREATE NEW SESSION
// =============================================================

async fn create_new_session(
    connection: &Connection,
) -> Result<ActiveSession, Box<dyn std::error::Error>> {
    println!();
    println!("Creating new PAYPHONE Session");

    //
    // Первое сообщение клиента.
    //
    let whats_up = WhatsUpDude::new(CLIENT_VERSION, CLIENT_CAPABILITIES);

    let frame = Frame {
        version: PROTOCOL_VERSION,

        frame_type: FrameType::WhatsUpDude,

        flags: 0,

        sequence: 1,

        payload: whats_up.encode(),
    };

    println!("What's up, dude?");

    connection.send_datagram_wait(frame.encode()).await?;

    println!("WhatsUpDude sent");

    //
    // Получаем AllGoodDude.
    //
    let response_frame = receive_frame(connection).await?;

    if response_frame.frame_type != FrameType::AllGoodDude {
        return Err(format!("expected AllGoodDude, got {:?}", response_frame.frame_type).into());
    }

    let all_good = AllGoodDude::decode(response_frame.payload)?;

    println!("All good, dude.");

    //
    // Сохраняем:
    //
    // session_id
    // +
    // server_nonce как resume token.
    //
    save_session(all_good.session_id, all_good.server_nonce)?;

    println!("Session saved to {}", SESSION_FILE);

    Ok(ActiveSession {
        session_id: all_good.session_id,

        assigned_ipv4: all_good.assigned_ipv4,

        mtu: all_good.mtu,

        capabilities: all_good.capabilities,
    })
}

// =============================================================
// MAIN
// =============================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    //
    // PAYPHONE server address.
    //
    let server_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DEFAULT_PORT);

    println!("PAYPHONE client starting");

    println!("Server: {}", server_address);

    //
    // Создаём QUIC client Endpoint.
    //
    let endpoint = create_client_endpoint()?;

    println!("Connecting with QUIC + TLS 1.3...");

    //
    // Создаём QUIC Connection.
    //
    //
    // SERVER_NAME:
    //
    // localhost
    //
    // rustls проверяет certificate
    // именно для этого имени.
    //
    let connection = endpoint.connect(server_address, SERVER_NAME)?.await?;

    println!("QUIC + TLS 1.3 connected");

    println!("Remote: {}", connection.remote_address());

    //
    // =========================================================
    // SESSION RESUME / CREATE
    // =========================================================
    //

    let active_session = if Path::new(SESSION_FILE).exists() {
        //
        // Файл есть.
        //
        // Пробуем восстановить Session.
        //
        match load_session() {
            Some(saved) => {
                match try_resume(&connection, saved).await? {
                    //
                    // Resume успешен.
                    //
                    Some(session) => {
                        println!("PAYPHONE SESSION RESUMED");

                        session
                    }

                    //
                    // Session уже умерла,
                    // сервер был перезапущен,
                    // token неправильный и т.д.
                    //
                    None => {
                        println!("Old Session unavailable");

                        //
                        // Удаляем старый state.
                        //
                        let _ = fs::remove_file(SESSION_FILE);

                        create_new_session(&connection).await?
                    }
                }
            }

            None => {
                //
                // Файл есть,
                // но содержимое повреждено.
                //
                println!("Saved Session is invalid");

                let _ = fs::remove_file(SESSION_FILE);

                create_new_session(&connection).await?
            }
        }
    } else {
        //
        // Первый запуск.
        //
        create_new_session(&connection).await?
    };

    // =========================================================
    // SESSION INFO
    // =========================================================

    println!();

    print!("Session ID: ");

    for byte in active_session.session_id {
        print!("{:02x}", byte);
    }

    println!();

    println!(
        "IPv4: {}.{}.{}.{}",
        active_session.assigned_ipv4[0],
        active_session.assigned_ipv4[1],
        active_session.assigned_ipv4[2],
        active_session.assigned_ipv4[3],
    );

    println!("MTU: {}", active_session.mtu);

    println!("Capabilities: {}", active_session.capabilities);

    // =========================================================
    // DATA CLIENT -> SERVER
    // =========================================================

    println!();
    println!("Sending PAYPHONE DATA...");

    //
    // Пока здесь текст.
    //
    // На этапе TUN здесь будет:
    //
    // настоящий IPv4/IPv6 packet.
    //
    let data = Data::new(
        active_session.session_id,
        1,
        Bytes::from_static(b"Hello through encrypted PAYPHONE"),
    );

    let data_frame = Frame {
        version: PROTOCOL_VERSION,

        frame_type: FrameType::Data,

        flags: 0,

        sequence: 3,

        payload: data.encode(),
    };

    connection.send_datagram_wait(data_frame.encode()).await?;

    println!("DATA sent through QUIC");

    // =========================================================
    // DATA SERVER -> CLIENT
    // =========================================================

    let response_frame = receive_frame(&connection).await?;

    if response_frame.frame_type != FrameType::Data {
        return Err(format!("expected DATA, got {:?}", response_frame.frame_type).into());
    }

    let response_data = Data::decode(response_frame.payload)?;

    //
    // Проверяем Session ID.
    //
    if response_data.session_id != active_session.session_id {
        return Err("DATA belongs to another PAYPHONE Session".into());
    }

    let text = String::from_utf8_lossy(&response_data.payload);

    println!("Server DATA: {}", text);

    // =========================================================
    // PING
    // =========================================================

    println!();
    println!("Sending PING...");

    let ping = Ping::new(active_session.session_id, 1);

    let ping_frame = Frame {
        version: PROTOCOL_VERSION,

        frame_type: FrameType::Ping,

        flags: 0,

        sequence: 5,

        payload: ping.encode(),
    };

    connection.send_datagram_wait(ping_frame.encode()).await?;

    println!("PING sent");

    // =========================================================
    // PONG
    // =========================================================

    let pong_frame = receive_frame(&connection).await?;

    if pong_frame.frame_type != FrameType::Pong {
        return Err(format!("expected PONG, got {:?}", pong_frame.frame_type).into());
    }

    let pong = Pong::decode(pong_frame.payload)?;

    if pong.session_id != active_session.session_id {
        return Err("PONG belongs to another PAYPHONE Session".into());
    }

    if pong.ping_id != 1 {
        return Err(format!("wrong PONG ping_id: {}", pong.ping_id).into());
    }

    println!("PONG received");

    println!("PAYPHONE connection is alive");

    // =========================================================
    // CLOSE QUIC
    // =========================================================

    //
    // Закрываем физическое QUIC connection.
    //
    // PAYPHONE Session на сервере
    // при этом остаётся жить,
    // поэтому следующий запуск
    // сможет сделать Resume.
    //
    connection.close(0u32.into(), b"client finished");

    //
    // Ждём, пока Endpoint закончит
    // закрытие соединения.
    //
    endpoint.wait_idle().await;

    println!();
    println!("QUIC connection closed");

    println!("PAYPHONE Session remains resumable");

    Ok(())
}
