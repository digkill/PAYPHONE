use std::{
    cell::RefCell,
    collections::VecDeque,
    fmt,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};

use crate::obfuscation::ObfuscationKey;

thread_local! {
    // Each runtime worker reuses its own wire buffer; sockets do not contend
    // on a shared allocation pool. Contents are already QUIC ciphertext.
    static TRANSMIT_BUFFER: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

//
// Оборачивает реальный AsyncUdpSocket и прозрачно для quinn
// обфусцирует/деобфусцирует каждую датаграмму. Адресация (кому
// отправляем, от кого получили) не трогается — только байты payload.
//
// GSO: Quinn may hand us several equal-sized datagrams in one
// Transmit (`segment_size`). UDP_SEGMENT requires the *wire* chunks
// to stay equal, so every segment in that batch uses the same pad
// length. A single datagram still gets a fresh random pad (0–32).
//
// GRO: the kernel may coalesce equal-sized datagrams into one
// RecvMeta (`stride` < `len`). Each stride chunk is deobfuscated
// independently, then compacted so Quinn can split on plaintext
// stride the same way it would on a native GRO buffer.
//
pub struct ObfuscatedSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    key: ObfuscationKey,
    dev_mode: bool,
    trace_stats: bool,
    pending: Mutex<VecDeque<PendingRecv>>,
}

struct PendingRecv {
    data: Bytes,
    meta: RecvMeta,
}

impl ObfuscatedSocket {
    //
    // `dev_mode` включает диагностическое логирование каждой сырой
    // датаграммы (размер + отправитель) до попытки деобфускации.
    // По умолчанию (false) сокет остаётся тихим — это часть модели
    // защиты от DPI-пробинга: сервер не выдаёт вообще никакой
    // реакции на нераспознанный трафик. Включать только при
    // диагностике связности (`PAYPHONE_DEV_MODE=true`).
    //
    pub fn new(inner: Arc<dyn AsyncUdpSocket>, key: ObfuscationKey, dev_mode: bool) -> Self {
        Self {
            inner,
            key,
            dev_mode,
            trace_stats: std::env::var("PAYPHONE_QUIC_STATS").ok().as_deref() == Some("1"),
            pending: Mutex::new(VecDeque::new()),
        }
    }

    fn send_with_buffer(&self, transmit: &Transmit<'_>, wire: &mut Vec<u8>) -> io::Result<()> {
        let segment_size = obfuscate_transmit(&self.key, transmit, wire)?;
        self.inner.try_send(&Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: wire,
            segment_size,
            src_ip: transmit.src_ip,
        })
    }
}

fn obfuscate_transmit(
    key: &ObfuscationKey,
    transmit: &Transmit<'_>,
    wire: &mut Vec<u8>,
) -> io::Result<Option<usize>> {
    wire.clear();
    let segment_size = transmit
        .segment_size
        .filter(|size| *size > 0 && *size < transmit.contents.len());

    let Some(segment_size) = segment_size else {
        key.obfuscate_padded_into(transmit.contents, ObfuscationKey::gso_pad_len(), wire)?;
        return Ok(None);
    };

    let pad_len = ObfuscationKey::gso_pad_len();

    wire.reserve(
        transmit.contents.len() + transmit.contents.len().div_ceil(segment_size) * (10 + pad_len),
    );
    let mut wire_segment = None;

    for chunk in transmit.contents.chunks(segment_size) {
        let start = wire.len();
        key.obfuscate_padded_into(chunk, pad_len, wire)?;

        if chunk.len() == segment_size {
            wire_segment = Some(wire.len() - start);
        }
    }

    let wire_segment = wire_segment.filter(|size| *size < wire.len());

    Ok(wire_segment)
}

impl fmt::Debug for ObfuscatedSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObfuscatedSocket")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Decoded {
    Rejected,
    Uniform,
    Mixed(Vec<usize>),
}

fn deobfuscate_into(key: &ObfuscationKey, buf: &mut [u8], meta: &mut RecvMeta) -> Decoded {
    let total = meta.len;

    if total == 0 || total > buf.len() {
        return Decoded::Rejected;
    }

    let stride = if meta.stride == 0 {
        total
    } else {
        meta.stride.min(total)
    };

    let mut first_len = None;
    let mut previous_len = 0;
    let mut segments = 0;
    let mut mixed: Option<Vec<usize>> = None;
    let mut out = 0;
    let mut offset = 0;

    while offset < total {
        let end = (offset + stride).min(total);

        if let Some(plain) = key.deobfuscate_in_place(&mut buf[offset..end]) {
            let len = plain.len();
            if len != 0 {
                if let Some(first) = first_len {
                    // Equal wire strides can hide different plaintext sizes
                    // because padding varies. RecvMeta cannot represent this
                    // mix: retain packet boundaries instead of dropping data.
                    if mixed.is_none() && (previous_len != first || len > first) {
                        let mut lengths = vec![first; segments];
                        lengths[segments - 1] = previous_len;
                        mixed = Some(lengths);
                    }
                } else {
                    first_len = Some(len);
                }
                buf.copy_within(offset + plain.start..offset + plain.end, out);
                out += len;
                previous_len = len;
                segments += 1;
                if let Some(lengths) = &mut mixed {
                    lengths.push(len);
                }
            }
        }

        offset += stride;
    }

    let Some(first_len) = first_len else {
        return Decoded::Rejected;
    };
    meta.len = out;
    meta.stride = first_len.max(1);

    match mixed {
        Some(lengths) => Decoded::Mixed(lengths),
        None => Decoded::Uniform,
    }
}

impl AsyncUdpSocket for ObfuscatedSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        //
        // Готовность сокета к записи не зависит от обфускации —
        // делегируем напрямую внутреннему сокету.
        //
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        TRANSMIT_BUFFER.with(|buffer| match buffer.try_borrow_mut() {
            Ok(mut buffer) => self.send_with_buffer(transmit, &mut buffer),
            // Also support socket adapters that reenter try_send on this thread.
            Err(_) => self.send_with_buffer(transmit, &mut Vec::new()),
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // Queue at most one kernel receive batch. Drain it before reading more
        // so splitting GRO never reorders packets past Quinn's replay window.
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if !pending.is_empty() {
            let count = pending.len().min(bufs.len()).min(meta.len());
            for (packet, buf) in pending.iter().zip(bufs.iter()).take(count) {
                if packet.data.len() > buf.len() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "receive buffer too small for queued datagram",
                    )));
                }
            }
            for index in 0..count {
                let packet = pending.pop_front().unwrap();
                bufs[index][..packet.data.len()].copy_from_slice(&packet.data);
                meta[index] = packet.meta;
            }
            return Poll::Ready(Ok(count));
        }
        loop {
            let count = ready!(self.inner.poll_recv(cx, bufs, meta))?;

            if count == 0 {
                return Poll::Ready(Ok(0));
            }

            let mut kept = 0;

            for index in 0..count {
                if self.dev_mode {
                    eprintln!(
                        "PAYPHONE: raw datagram {} bytes from {}",
                        meta[index].len, meta[index].addr
                    );
                }

                match deobfuscate_into(&self.key, &mut bufs[index], &mut meta[index]) {
                    Decoded::Rejected => continue,
                    Decoded::Uniform if !pending.is_empty() => {
                        pending.push_back(PendingRecv {
                            data: Bytes::copy_from_slice(&bufs[index][..meta[index].len]),
                            meta: meta[index],
                        });
                        continue;
                    }
                    Decoded::Mixed(lengths) => {
                        let data = Bytes::copy_from_slice(&bufs[index][..meta[index].len]);
                        let queued = !pending.is_empty();
                        let mut start = 0;
                        for (part, len) in lengths.iter().copied().enumerate() {
                            if queued || part != 0 {
                                let mut part_meta = meta[index];
                                part_meta.len = len;
                                part_meta.stride = len;
                                pending.push_back(PendingRecv {
                                    data: data.slice(start..start + len),
                                    meta: part_meta,
                                });
                            }
                            start += len;
                        }
                        if self.trace_stats {
                            eprintln!("QUIC GRO split: {} datagrams retained", lengths.len());
                        }
                        if queued {
                            continue;
                        }
                        meta[index].len = lengths[0];
                        meta[index].stride = lengths[0];
                    }
                    Decoded::Uniform => {}
                }
                if kept != index {
                    let len = meta[index].len;

                    let (earlier, current) = bufs.split_at_mut(index);
                    earlier[kept][..len].copy_from_slice(&current[0][..len]);

                    meta[kept] = meta[index];
                }

                kept += 1;
            }

            if kept > 0 {
                return Poll::Ready(Ok(kept));
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(len: usize, stride: usize) -> RecvMeta {
        RecvMeta {
            addr: "127.0.0.1:1".parse().unwrap(),
            len,
            stride,
            ecn: None,
            dst_ip: None,
        }
    }

    #[test]
    fn gso_batch_roundtrips_through_gro_with_short_final_segment() {
        let key = ObfuscationKey::from_passphrase("gso-roundtrip-test");
        let payload: Vec<_> = (0..3 * 1140 + 233).map(|n| n as u8).collect();
        let transmit = Transmit {
            destination: "127.0.0.1:1".parse().unwrap(),
            ecn: None,
            contents: &payload,
            segment_size: Some(1140),
            src_ip: None,
        };
        let mut wire = Vec::with_capacity(8192);
        let allocation = wire.as_ptr();
        for _ in 0..100 {
            let segment = obfuscate_transmit(&key, &transmit, &mut wire)
                .unwrap()
                .unwrap();
            assert!((1150..=1182).contains(&segment));
            let decoded: Vec<_> = wire
                .chunks(segment)
                .flat_map(|chunk| key.deobfuscate(chunk).unwrap())
                .collect();
            assert_eq!(decoded, payload);
            let mut meta = metadata(wire.len(), segment);
            assert_eq!(
                deobfuscate_into(&key, &mut wire, &mut meta),
                Decoded::Uniform
            );
            assert_eq!(meta.len, payload.len());
            assert_eq!(meta.stride, 1140);
            assert_eq!(&wire[..meta.len], payload);
            assert_eq!(allocation, wire.as_ptr());
        }
    }

    #[test]
    fn gro_skips_noise_without_corrupting_following_segments() {
        let key = ObfuscationKey::from_passphrase("gro-noise-test");
        let good = key.obfuscate_padded(&[0xAB; 40], 0).unwrap();
        let mut noise = key.obfuscate_padded(&[], 0).unwrap();
        noise.resize(good.len(), 0);
        let mut wire = [noise.clone(), good.clone(), noise, good].concat();
        let mut meta = metadata(wire.len(), 50);
        assert_eq!(
            deobfuscate_into(&key, &mut wire, &mut meta),
            Decoded::Uniform
        );
        assert_eq!((meta.len, meta.stride), (80, 40));
        assert_eq!(&wire[..meta.len], &[0xAB; 80]);
    }

    #[test]
    fn gro_retains_boundaries_when_plaintext_sizes_differ() {
        let key = ObfuscationKey::from_passphrase("gro-size-mix-test");
        let first = key.obfuscate_padded(&[1; 40], 20).unwrap();
        let second = key.obfuscate_padded(&[2; 60], 0).unwrap();
        assert_eq!(first.len(), second.len());
        let mut wire = [first, second].concat();
        let mut meta = metadata(wire.len(), 70);
        assert_eq!(
            deobfuscate_into(&key, &mut wire, &mut meta),
            Decoded::Mixed(vec![40, 60])
        );
        assert_eq!(meta.len, 100);
        assert_eq!(&wire[..40], &[1; 40]);
        assert_eq!(&wire[40..100], &[2; 60]);
    }

    #[test]
    fn gro_compacts_equal_plaintext_segments() {
        let key = ObfuscationKey::from_passphrase("test-passphrase");

        let first = key.obfuscate_padded(&[1u8; 40], 4).unwrap();

        let second = key.obfuscate_padded(&[2u8; 40], 4).unwrap();

        assert_eq!(first.len(), second.len());

        let mut buf = [0u8; 512];

        buf[..first.len()].copy_from_slice(&first);

        buf[first.len()..first.len() + second.len()].copy_from_slice(&second);

        let mut meta = RecvMeta {
            addr: "127.0.0.1:1".parse().unwrap(),
            len: first.len() + second.len(),
            stride: first.len(),
            ecn: None,
            dst_ip: None,
        };

        assert_eq!(
            deobfuscate_into(&key, &mut buf, &mut meta),
            Decoded::Uniform
        );

        assert_eq!(meta.stride, 40);

        assert_eq!(meta.len, 80);

        assert_eq!(&buf[..40], &[1u8; 40]);

        assert_eq!(&buf[40..80], &[2u8; 40]);
    }

    #[test]
    fn gro_retains_short_middle_and_following_segments() {
        let key = ObfuscationKey::from_passphrase("gro-short-middle-test");
        let mut wire = [
            key.obfuscate_padded(&[1; 60], 0).unwrap(),
            key.obfuscate_padded(&[2; 40], 20).unwrap(),
            key.obfuscate_padded(&[3; 50], 10).unwrap(),
        ]
        .concat();
        let mut meta = metadata(wire.len(), 70);
        assert_eq!(
            deobfuscate_into(&key, &mut wire, &mut meta),
            Decoded::Mixed(vec![60, 40, 50])
        );
        assert_eq!(&wire[..150], [&[1; 60][..], &[2; 40], &[3; 50]].concat());
    }

    #[derive(Debug)]
    struct BatchSocket {
        batch: Mutex<Option<Vec<(Vec<u8>, usize)>>>,
        polls: std::sync::atomic::AtomicUsize,
    }

    impl AsyncUdpSocket for BatchSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            unreachable!("receive-only test socket")
        }
        fn try_send(&self, _: &Transmit<'_>) -> io::Result<()> {
            unreachable!("receive-only test socket")
        }
        fn poll_recv(
            &self,
            _: &mut Context,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            self.polls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let Some(batch) = self.batch.lock().unwrap().take() else {
                return Poll::Pending;
            };
            let count = batch.len();
            for (index, (wire, stride)) in batch.into_iter().enumerate() {
                bufs[index][..wire.len()].copy_from_slice(&wire);
                meta[index] = metadata(wire.len(), stride);
            }
            Poll::Ready(Ok(count))
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:1".parse().unwrap())
        }
        fn max_receive_segments(&self) -> usize {
            64
        }
    }

    #[tokio::test]
    async fn mixed_gro_queue_preserves_order_across_receive_batches() {
        let key = ObfuscationKey::from_passphrase("gro-order-test");
        let inner = Arc::new(BatchSocket {
            batch: Mutex::new(Some(vec![
                (
                    [
                        key.obfuscate_padded(&[1; 40], 20).unwrap(),
                        key.obfuscate_padded(&[2; 60], 0).unwrap(),
                    ]
                    .concat(),
                    70,
                ),
                (
                    [
                        key.obfuscate_padded(&[3; 70], 20).unwrap(),
                        key.obfuscate_padded(&[4; 90], 0).unwrap(),
                    ]
                    .concat(),
                    100,
                ),
                (
                    [
                        key.obfuscate_padded(&[5; 100], 0).unwrap(),
                        key.obfuscate_padded(&[6; 100], 0).unwrap(),
                    ]
                    .concat(),
                    110,
                ),
            ])),
            polls: std::sync::atomic::AtomicUsize::new(0),
        });
        let socket = ObfuscatedSocket::new(inner.clone(), key, false);
        let mut buffers = [[0u8; 512]; 3];
        let mut received = Vec::new();
        for expected_count in [1, 3, 1] {
            let mut bufs: Vec<_> = buffers.iter_mut().map(|buf| IoSliceMut::new(buf)).collect();
            let mut meta = [metadata(0, 0); 3];
            let count = std::future::poll_fn(|cx| socket.poll_recv(cx, &mut bufs, &mut meta))
                .await
                .unwrap();
            assert_eq!(count, expected_count);
            for index in 0..count {
                received.extend(
                    bufs[index][..meta[index].len]
                        .chunks(meta[index].stride)
                        .map(<[u8]>::to_vec),
                );
            }
        }
        assert_eq!(
            received,
            vec![
                vec![1; 40],
                vec![2; 60],
                vec![3; 70],
                vec![4; 90],
                vec![5; 100],
                vec![6; 100]
            ]
        );
        assert_eq!(inner.polls.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert!(socket.pending.lock().unwrap().is_empty());
    }
}
