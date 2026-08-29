use std::time::Duration;

use bytes::Bytes;
use quinn::Connection;
use tokio::{signal, sync::mpsc, time};

use payphone_core::{
    Frame, FrameType, PROTOCOL_VERSION, access_denied_dude::AccessDeniedDude,
    close::{Close, CloseReason}, data::Data, ping::Ping, pong::Pong, rekey::Rekey,
};
use payphone_transport::https_front::TlsFrameWriter;
use payphone_tun::{
    PAYPHONE_MTU, PAYPHONE_MTU_MAX, create_client_tun, mtu_from_datagram_budget, set_interface_mtu,
};

use crate::{ActiveSession, matrix};

pub enum VpnSink {
    Quic(Connection),

    Tls(TlsFrameWriter),
}

impl VpnSink {
    pub async fn send(&self, bytes: Bytes) -> Result<bool, Box<dyn std::error::Error>> {
        match self {
            Self::Quic(connection) => payphone_transport::send_vpn_datagram(connection, bytes)
                .map_err(|error| format!("QUIC connection lost: {error}").into()),

            Self::Tls(writer) => {
                writer.send_bytes(&bytes).await?;

                Ok(true)
            }
        }
    }

    fn tun_mtu(&self) -> u16 {
        match self {
            Self::Quic(connection) => connection
                .max_datagram_size()
                .map(mtu_from_datagram_budget)
                .unwrap_or(PAYPHONE_MTU),

            Self::Tls(_) => PAYPHONE_MTU_MAX,
        }
    }
}

pub enum TunnelExit {
    Stopped,

    Disconnected,

    Denied(String),
}

pub struct QuicShutdown {
    pub connection: Connection,
}

pub async fn run_tunnel(
    active: ActiveSession,
    server_address: std::net::SocketAddr,
    sink: VpnSink,
    mut incoming: mpsc::Receiver<Frame>,
    quic: Option<QuicShutdown>,
) -> Result<TunnelExit, Box<dyn std::error::Error>> {
    let mut tun_mtu = sink.tun_mtu();

    let tun = create_client_tun(active.assigned_ipv4, tun_mtu)?;

    crate::matrix::status("PAYPHONE TUN created");

    matrix::status(&format!("VPN MTU: {tun_mtu}"));

    let tun_name = tun.name()?;

    let mut full_tunnel =
        match payphone_tun::routing::FullTunnelGuard::install(server_address, &tun_name) {
            Ok(guard) => {
                matrix::status(
                    "Full-tunnel routing enabled (all traffic now goes through PAYPHONE)",
                );

                matrix::tunnel_open_banner();

                Some(guard)
            }

            Err(error) => {
                eprintln!(
                    "Could not enable full-tunnel routing ({error}); \
                 only 10.77.0.0/24 will go through the VPN"
                );

                None
            }
        };

    matrix::status("Try: ping 10.77.0.1");

    let mut tun_buffer = vec![0u8; 65535];

    let mut packet_id: u64 = 1;

    let mut frame_sequence: u64 = 10;

    let mut ping_id: u64 = 1;

    let mut flow = matrix::FlowIndicator::new();

    let mut route_watch = time::interval(Duration::from_millis(400));

    route_watch.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

    let mut rain_tick = time::interval(Duration::from_millis(50));

    rain_tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            result = tun.recv(&mut tun_buffer) => {
                let size = result?;

                if size == 0 {
                    continue;
                }

                let data = Data::new(
                    active.session_id,
                    packet_id,
                    Bytes::copy_from_slice(&tun_buffer[..size]),
                );

                let frame = Frame {
                    version: PROTOCOL_VERSION,
                    frame_type: FrameType::Data,
                    flags: 0,
                    sequence: frame_sequence,
                    payload: data.encode(),
                };

                match sink.send(frame.encode()).await {
                    Ok(true) => flow.pulse('▸'),

                    Ok(false) => {}

                    Err(_) => {
                        flow.finish_line();

                        drop(full_tunnel.take());

                        close_quic(quic).await;

                        return Ok(TunnelExit::Disconnected);
                    }
                }

                packet_id = packet_id.wrapping_add(1);

                frame_sequence = frame_sequence.wrapping_add(1);
            }

            result = incoming.recv() => {
                let Some(frame) = result else {
                    flow.finish_line();

                    drop(full_tunnel.take());

                    close_quic(quic).await;

                    return Ok(TunnelExit::Disconnected);
                };

                match frame.frame_type {
                    FrameType::Data => {
                        let data = Data::decode(frame.payload)?;

                        if data.session_id != active.session_id {
                            continue;
                        }

                        tun.send(&data.payload).await?;

                        flow.pulse('◂');
                    }

                    FrameType::Pong => {
                        let pong = Pong::decode(frame.payload)?;

                        if pong.session_id == active.session_id {
                            flow.pulse('◂');
                        }
                    }

                    FrameType::Rekey => {
                        if let Ok(Rekey::Token {
                            session_id,
                            nonce,
                        }) = Rekey::decode(frame.payload)
                        {
                            if session_id == active.session_id {
                                let _ = crate::save_session(session_id, nonce);

                                let confirm = Frame {
                                    version: PROTOCOL_VERSION,
                                    frame_type: FrameType::Rekey,
                                    flags: 0,
                                    sequence: frame_sequence,
                                    payload: Rekey::token(session_id, nonce).encode(),
                                };

                                let _ = sink.send(confirm.encode()).await;

                                frame_sequence = frame_sequence.wrapping_add(1);
                            }
                        }
                    }

                    FrameType::Close => {
                        let close = Close::decode(frame.payload)?;

                        if close.session_id != active.session_id {
                            continue;
                        }

                        crate::forget_session();

                        flow.finish_line();

                        drop(full_tunnel.take());

                        close_quic(quic).await;

                        return Ok(match close.reason {
                            CloseReason::Replaced => {
                                TunnelExit::Denied("PAYPHONE session replaced by another device".into())
                            }

                            CloseReason::ServerShutdown => {
                                TunnelExit::Denied("PAYPHONE server closed the session".into())
                            }

                            CloseReason::ClientShutdown => TunnelExit::Stopped,
                        });
                    }

                    FrameType::AccessDeniedDude => {
                        let denied = AccessDeniedDude::decode(frame.payload)?;

                        crate::forget_session();

                        flow.finish_line();

                        drop(full_tunnel.take());

                        close_quic(quic).await;

                        return Ok(TunnelExit::Denied(format!(
                            "PAYPHONE access revoked: {:?}",
                            denied.reason
                        )));
                    }

                    _ => {}
                }
            }

            _ = time::sleep(crate::random_ping_interval()) => {
                let ping = Ping::new(active.session_id, ping_id);

                let frame = Frame {
                    version: PROTOCOL_VERSION,
                    frame_type: FrameType::Ping,
                    flags: 0,
                    sequence: frame_sequence,
                    payload: ping.encode(),
                };

                let _ = sink.send(frame.encode()).await;

                ping_id = ping_id.wrapping_add(1);

                frame_sequence = frame_sequence.wrapping_add(1);
            }

            _ = signal::ctrl_c() => {
                flow.finish_line();

                matrix::status("Stopping PAYPHONE VPN");

                let close = Frame {
                    version: PROTOCOL_VERSION,
                    frame_type: FrameType::Close,
                    flags: 0,
                    sequence: frame_sequence,
                    payload: Close::new(active.session_id, CloseReason::ClientShutdown).encode(),
                };

                let _ = sink.send(close.encode()).await;

                crate::forget_session();

                drop(full_tunnel.take());

                matrix::status("Internet restored");

                close_quic(quic).await;

                return Ok(TunnelExit::Stopped);
            }

            _ = rain_tick.tick() => {
                flow.tick();
            }

            _ = route_watch.tick() => {
                if let Some(ref guard) = full_tunnel {
                    guard.ensure_tunnel_routes();
                }

                let next_mtu = sink.tun_mtu();

                if next_mtu != tun_mtu {
                    set_interface_mtu(tun.as_ref(), next_mtu);

                    tun_mtu = next_mtu;

                    matrix::status(&format!("VPN MTU: {tun_mtu}"));
                }
            }
        }
    }
}

async fn close_quic(quic: Option<QuicShutdown>) {
    if let Some(quic) = quic {
        quic.connection.close(0u32.into(), b"client shutdown");
    }
}
