//! Local transport benchmark. Does not create a TUN, change routes, or contact a VPS.
use std::{env, net::SocketAddr, time::Duration};

use bytes::Bytes;
use payphone_core::{Frame, data::Data};
use payphone_transport::{
    client::create_client_endpoint,
    identity::{ClientTlsConfig, SERVER_NAME, ServerTlsConfig, ensure_dev_identity},
    obfuscation::ObfuscationKey,
    send_vpn_datagram,
    server::create_server_endpoint,
};
use tokio::time::{Instant, MissedTickBehavior};

struct Received {
    packets: u64,
    bytes: u64,
    per_second: Vec<u64>,
}

struct Sent {
    packets: u64,
    per_second: Vec<u64>,
}

async fn receive(c: quinn::Connection, start: Instant, seconds: u64) -> Received {
    let until = start + Duration::from_millis(seconds * 1000 + 500);
    let mut received = Received {
        packets: 0,
        bytes: 0,
        per_second: vec![0; seconds as usize],
    };
    loop {
        match tokio::time::timeout_at(until, c.read_datagram()).await {
            Ok(Ok(frame)) => {
                if let Ok(frame) = Frame::decode(frame) {
                    if let Ok(data) = Data::decode(frame.payload) {
                        received.packets += 1;
                        received.bytes += data.payload.len() as u64;
                        let second = (Instant::now() - start).as_secs() as usize;
                        if let Some(bytes) = received.per_second.get_mut(second) {
                            *bytes += data.payload.len() as u64;
                        }
                    }
                }
            }
            _ => return received,
        }
    }
}

async fn send(
    c: quinn::Connection,
    payload: Bytes,
    start: Instant,
    seconds: u64,
    mbps: u64,
    reuse_frame: bool,
) -> Sent {
    let end = start + Duration::from_secs(seconds);
    let mut interval = tokio::time::interval(Duration::from_millis(1));
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut sent = 0;
    let mut per_second = vec![0; seconds as usize];
    let template = reuse_frame.then(|| Data::encode_frame([0; 16], 1, 1, &payload).unwrap());
    while Instant::now() < end {
        interval.tick().await;
        let elapsed = Instant::now() - start;
        let target = elapsed.as_nanos() * u128::from(mbps) * 125_000 / 1_000_000_000 / 1100;
        // Limit catch-up work so a delayed task cannot monopolize a runtime worker.
        let count = (target.saturating_sub(sent as u128)).min(1024) as u64;
        for _ in 0..count {
            let frame = match &template {
                Some(frame) => frame.clone(),
                None => Data::encode_frame([0; 16], sent, sent, &payload).unwrap(),
            };
            if send_vpn_datagram(&c, frame).unwrap_or(false) {
                sent += 1;
                if let Some(count) = per_second.get_mut(elapsed.as_secs() as usize) {
                    *count += 1;
                }
            }
        }
    }
    Sent {
        packets: sent,
        per_second,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().collect();
    let clients: usize = args.get(1).map(|s| s.parse()).transpose()?.unwrap_or(1);
    let mbps: u64 = args.get(2).map(|s| s.parse()).transpose()?.unwrap_or(100);
    let seconds: u64 = args.get(3).map(|s| s.parse()).transpose()?.unwrap_or(5);
    let min_mbps: Option<f64> = env::var("PAYPHONE_BENCH_MIN_MBPS")
        .ok()
        .map(|s| s.parse())
        .transpose()?;
    let max_loss: Option<f64> = env::var("PAYPHONE_BENCH_MAX_LOSS_PCT")
        .ok()
        .map(|s| s.parse())
        .transpose()?;
    if min_mbps
        .into_iter()
        .chain(max_loss)
        .any(|v| !v.is_finite() || v < 0.0)
    {
        return Err("benchmark thresholds must be finite and nonnegative".into());
    }
    if clients == 0 || clients > 1000 || mbps == 0 || seconds == 0 {
        return Err(
            "usage: bench_datagrams [clients:1..1000] [Mbps per client per direction] [seconds]"
                .into(),
        );
    }
    ensure_dev_identity()?;
    let key = ObfuscationKey::from_passphrase("local-benchmark-only-secret");
    let server = create_server_endpoint(
        "127.0.0.1:0".parse::<SocketAddr>()?,
        key.clone(),
        false,
        &ServerTlsConfig::default(),
    )?;
    let client = create_client_endpoint(key, false, None, None, &ClientTlsConfig::default())?;
    let mut pairs = Vec::new();
    for _ in 0..clients {
        let acceptor = server.clone();
        let accepted = tokio::spawn(async move { acceptor.accept().await.unwrap().await });
        let c = tokio::time::timeout(
            Duration::from_secs(10),
            client.connect(server.local_addr()?, SERVER_NAME)?,
        )
        .await??;
        let s = tokio::time::timeout(Duration::from_secs(10), accepted).await???;
        pairs.push((c, s));
    }
    let payload = Bytes::from(vec![0xAB; 1100]);
    let reuse_frame = env::var("PAYPHONE_BENCH_REUSE_FRAME").ok().as_deref() == Some("1");
    let start = Instant::now();
    let mut uploads = Vec::new();
    let mut downloads = Vec::new();
    let mut senders = Vec::new();
    let mut connections = Vec::new();
    for (c, s) in pairs {
        connections.push((c.clone(), s.clone()));
        uploads.push(tokio::spawn(receive(s.clone(), start, seconds)));
        downloads.push(tokio::spawn(receive(c.clone(), start, seconds)));
        senders.push(tokio::spawn(send(
            c,
            payload.clone(),
            start,
            seconds,
            mbps,
            reuse_frame,
        )));
        senders.push(tokio::spawn(send(
            s,
            payload.clone(),
            start,
            seconds,
            mbps,
            reuse_frame,
        )));
    }
    let mut queued = 0;
    let mut source_windows = [vec![0; seconds as usize], vec![0; seconds as usize]];
    for (index, task) in senders.into_iter().enumerate() {
        let sent = task.await?;
        queued += sent.packets;
        for (count, packets) in source_windows[index % 2].iter_mut().zip(sent.per_second) {
            *count += packets;
        }
    }
    let mut received = 0;
    println!(
        "Frame encoding: {}",
        if reuse_frame {
            "reused template"
        } else {
            "fresh DATA frame per packet"
        }
    );
    println!(
        "Local QUIC + obfuscation + PAYPHONE frames; {clients} clients, target {mbps} Mbps/client/direction"
    );
    println!(
        "Tokio workers: {} (client and server share one process)",
        tokio::runtime::Handle::current().metrics().num_workers()
    );
    let mut windows = Vec::new();
    let mut minimum_mbps = f64::INFINITY;
    for (label, tasks) in [("upload", uploads), ("download", downloads)] {
        let mut bytes = 0;
        let mut packets = 0;
        let mut bins = vec![0u64; seconds as usize];
        for task in tasks {
            let report = task.await?;
            packets += report.packets;
            bytes += report.bytes;
            for (total, count) in bins.iter_mut().zip(report.per_second) {
                *total += count;
            }
        }
        received += packets;
        let warmup = if seconds > 5 { 3 } else { 0 };
        let min = bins[warmup..].iter().copied().min().unwrap_or(0);
        minimum_mbps = minimum_mbps.min(min as f64 * 8.0 / 1_000_000.0);
        println!(
            "{label}: {:.1} Mbps inner IP (includes drain), {packets} packets; minimum 1s after {warmup}s warmup: {:.1} Mbps",
            bytes as f64 * 8.0 / seconds as f64 / 1_000_000.0,
            min as f64 * 8.0 / 1_000_000.0,
        );
        windows.push(bins);
    }
    for second in 0..seconds as usize {
        println!(
            "second {:>3}: source_up={:.1} upload={:.1} source_down={:.1} download={:.1} Mbps",
            second + 1,
            source_windows[0][second] as f64 * 1100.0 * 8.0 / 1_000_000.0,
            windows[0][second] as f64 * 8.0 / 1_000_000.0,
            source_windows[1][second] as f64 * 1100.0 * 8.0 / 1_000_000.0,
            windows[1][second] as f64 * 8.0 / 1_000_000.0
        );
    }
    let mut transmitted = 0;
    for (index, (c, s)) in connections.iter().enumerate() {
        for (label, connection) in [("upload", c), ("download", s)] {
            let stats = connection.stats();
            transmitted += stats.frame_tx.datagram;
            println!(
                "client {index} {label}: tx_frames={} tx_udp={} lost_quic={} rtt_us={} cwnd={} free_queue={}",
                stats.frame_tx.datagram,
                stats.udp_tx.datagrams,
                stats.path.lost_packets,
                stats.path.rtt.as_micros(),
                stats.path.cwnd,
                connection.datagram_send_buffer_space()
            );
        }
    }
    println!(
        "Not transmitted from outgoing queues: {}; transmitted but not delivered: {}",
        queued.saturating_sub(transmitted),
        transmitted.saturating_sub(received)
    );
    let loss_pct = 100.0 * queued.saturating_sub(received) as f64 / queued.max(1) as f64;
    println!(
        "Queued {queued}, received {received}, undelivered {:.2}% (includes queue drops/drain deadline)",
        loss_pct
    );
    println!("Transport only: excludes TUN, NAT, server auth/limits, WAN and mobile bindings.");
    client.close(0u32.into(), b"benchmark complete");
    server.close(0u32.into(), b"benchmark complete");
    if min_mbps.is_some_and(|min| minimum_mbps < min) || max_loss.is_some_and(|max| loss_pct > max)
    {
        return Err(format!(
            "stability check failed: minimum={minimum_mbps:.2} Mbps, undelivered={loss_pct:.4}%"
        )
        .into());
    }
    if min_mbps.is_some() || max_loss.is_some() {
        println!("Stability check: PASS");
    }
    Ok(())
}
