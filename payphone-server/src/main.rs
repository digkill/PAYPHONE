use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use tokio::{signal, sync::RwLock, time};

use payphone_core::DEFAULT_PORT;

use payphone_transport::server::create_server_endpoint;

mod handler;
mod session;

use handler::handle_packet;
use session::SessionManager;

//
// Как часто проверяем,
// нет ли протухших PAYPHONE Sessions.
//
// Каждые 5 секунд.
//
const CLEANUP_INTERVAL: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    //
    // Адрес PAYPHONE server.
    //
    // Пока используем только localhost:
    //
    // 127.0.0.1:40404
    //
    // Когда пойдём на реальный сервер,
    // здесь будет:
    //
    // 0.0.0.0:40404
    //
    let server_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DEFAULT_PORT);

    //
    // Создаём QUIC Endpoint.
    //
    // Внутри:
    //
    // UDP
    // +
    // QUIC
    // +
    // TLS 1.3
    //
    let endpoint = create_server_endpoint(server_address)?;

    println!("PAYPHONE QUIC server listening on {}", server_address);

    //
    // Создаём ОДИН SessionManager
    // для всего сервера.
    //
    // Arc:
    //
    // несколько async task
    // используют один объект.
    //
    // RwLock:
    //
    // защищает SessionManager
    // от одновременного изменения.
    //
    let sessions = Arc::new(RwLock::new(SessionManager::new()));

    //
    // Создаём периодический таймер.
    //
    let mut cleanup_interval = time::interval(CLEANUP_INTERVAL);

    //
    // Первый interval tick
    // происходит сразу.
    //
    // Забираем его сейчас,
    // чтобы следующий произошёл
    // через реальные 5 секунд.
    //
    cleanup_interval.tick().await;

    println!("PAYPHONE server ready");

    //
    // Главный цикл сервера.
    //
    loop {
        //
        // Ждём одновременно:
        //
        // 1. новое QUIC connection
        //
        // 2. cleanup timer
        //
        // 3. Ctrl+C
        //
        tokio::select! {
            //
            // =====================================================
            // NEW QUIC CONNECTION
            // =====================================================
            //
            incoming =
                endpoint.accept()
            => {
                //
                // endpoint.accept()
                //
                // возвращает Option.
                //
                // Если Endpoint закрыт:
                //
                // None
                //
                let Some(incoming) =
                    incoming
                else {
                    println!(
                        "QUIC endpoint closed"
                    );

                    break;
                };

                //
                // Этой новой task понадобится
                // доступ к SessionManager.
                //
                // Arc::clone НЕ копирует
                // SessionManager.
                //
                // Создаётся ещё один владелец
                // того же объекта.
                //
                let sessions =
                    Arc::clone(
                        &sessions
                    );

                //
                // Каждый QUIC connection
                // обслуживаем отдельной
                // Tokio task.
                //
                tokio::spawn(
                    async move {
                        //
                        // incoming.await
                        //
                        // выполняет:
                        //
                        // QUIC handshake
                        // +
                        // TLS 1.3 handshake
                        //
                        let connection =
                            match incoming.await {
                                Ok(connection) => {
                                    connection
                                }

                                Err(error) => {
                                    println!(
                                        "QUIC handshake failed: {}",
                                        error
                                    );

                                    return;
                                }
                            };

                        //
                        // Физический адрес peer.
                        //
                        // Например:
                        //
                        // 127.0.0.1:53421
                        //
                        let client_address =
                            connection
                                .remote_address();

                        println!();
                        println!(
                            "QUIC + TLS connection established"
                        );

                        println!(
                            "Client: {}",
                            client_address
                        );

                        //
                        // Пока QUIC connection живёт,
                        // читаем application datagrams.
                        //
                        loop {
                            //
                            // read_datagram()
                            //
                            // возвращает уже расшифрованный
                            // payload QUIC datagram.
                            //
                            let packet =
                                match connection
                                    .read_datagram()
                                    .await
                                {
                                    Ok(packet) => {
                                        packet
                                    }

                                    Err(error) => {
                                        println!(
                                            "QUIC connection {} closed: {}",
                                            client_address,
                                            error
                                        );

                                        break;
                                    }
                                };

                            //
                            // Клонируем Connection handle.
                            //
                            // Сам QUIC connection
                            // не копируется.
                            //
                            let connection_clone =
                                connection.clone();

                            //
                            // Клонируем Arc
                            // SessionManager.
                            //
                            let sessions_clone =
                                Arc::clone(
                                    &sessions
                                );

                            //
                            // Каждый PAYPHONE Frame
                            // обрабатывается отдельной task.
                            //
                            tokio::spawn(
                                async move {
                                    handle_packet(
                                        connection_clone,
                                        sessions_clone,
                                        client_address,
                                        packet,
                                    )
                                    .await;
                                }
                            );
                        }
                    }
                );
            }


            //
            // =====================================================
            // SESSION CLEANUP
            // =====================================================
            //
            _ =
                cleanup_interval.tick()
            => {
                //
                // remove_expired()
                // изменяет SessionManager.
                //
                // Поэтому:
                //
                // write().await
                //
                let mut sessions =
                    sessions
                        .write()
                        .await;

                let removed =
                    sessions
                        .remove_expired();

                if removed > 0 {
                    println!();
                    println!(
                        "Removed {} expired session(s)",
                        removed
                    );

                    println!(
                        "Active sessions: {}",
                        sessions.len()
                    );
                }
            }


            //
            // =====================================================
            // CTRL+C
            // =====================================================
            //
            result =
                signal::ctrl_c()
            => {
                println!();

                match result {
                    Ok(()) => {
                        println!(
                            "PAYPHONE server shutting down"
                        );
                    }

                    Err(error) => {
                        println!(
                            "Ctrl+C signal error: {}",
                            error
                        );
                    }
                }

                break;
            }
        }
    }

    //
    // Корректно закрываем
    // все QUIC connections.
    //
    endpoint.close(0u32.into(), b"PAYPHONE server shutdown");

    //
    // Даём Quinn возможность
    // закончить отправку close packets.
    //
    endpoint.wait_idle().await;

    println!("PAYPHONE server stopped");

    Ok(())
}
