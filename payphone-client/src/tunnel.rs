use std::time::Duration;

use bytes::Bytes;
use quinn::{Connection, Endpoint};
use tokio::{signal, sync::mpsc, time};

use payphone_core::{
    Frame, FrameType, PROTOCOL_VERSION, access_denied_dude::AccessDeniedDude, data::Data, ping::Ping,
    pong::Pong,
};
use payphone_transport::https_front::TlsFrameWriter;
use payphone_tun::{PAYPHONE_MTU, create_client_tun};

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
}

pub struct QuicShutdown {
    pub connection: Connection,

    pub endpoint: Endpoint,
}

pub async fn run_tunnel(
    active: ActiveSession,
    server_address: std::net::SocketAddr,
    sink: VpnSink,
    mut incoming: mpsc::Receiver<Frame>,
    quic: Option<QuicShutdown>,
) -> Result<(), Box<dyn std::error::Error>> {
    let tun = create_client_tun(
        active.assigned_ipv4,
        if active.mtu == 0 {
            PAYPHONE_MTU
        } else {
            active.mtu
        },
    )?;

    crate::matrix::status("PAYPHONE TUN created");

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

                if sink.send(frame.encode()).await? {
                    flow.pulse('▸');
                }

                packet_id = packet_id.wrapping_add(1);

                frame_sequence = frame_sequence.wrapping_add(1);
            }

            result = incoming.recv() => {
                let Some(frame) = result else {
                    flow.finish_line();

                    drop(full_tunnel.take());

                    return Err("PAYPHONE connection closed".into());
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

                    FrameType::AccessDeniedDude => {
                        let denied = AccessDeniedDude::decode(frame.payload)?;

                        flow.finish_line();

                        drop(full_tunnel.take());

                        return Err(
                            format!("PAYPHONE access revoked: {:?}", denied.reason).into(),
                        );
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

                let _ = sink.send(frame.encode()).await?;

                ping_id = ping_id.wrapping_add(1);

                frame_sequence = frame_sequence.wrapping_add(1);
            }

            _ = signal::ctrl_c() => {
                flow.finish_line();

                matrix::status("Stopping PAYPHONE VPN");

                drop(full_tunnel.take());

                matrix::status("Internet restored");

                break;
            }

            _ = rain_tick.tick() => {
                flow.tick();
            }

            _ = route_watch.tick() => {
                if let Some(ref guard) = full_tunnel {
                    guard.ensure_tunnel_routes();
                }
            }
        }
    }

    drop(full_tunnel.take());

    if let Some(quic) = quic {
        quic.connection.close(0u32.into(), b"client shutdown");

        let _ = time::timeout(Duration::from_millis(800), quic.endpoint.wait_idle()).await;
    }

    Ok(())
}
