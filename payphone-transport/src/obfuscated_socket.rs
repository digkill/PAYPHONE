use std::{
    fmt,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};

use crate::obfuscation::ObfuscationKey;

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
        }
    }

    fn obfuscate_transmit(&self, transmit: &Transmit<'_>) -> io::Result<(Vec<u8>, Option<usize>)> {
        let segment_size = transmit
            .segment_size
            .filter(|size| *size > 0 && *size < transmit.contents.len());

        let Some(segment_size) = segment_size else {
            return Ok((self.key.obfuscate(transmit.contents)?, None));
        };

        let pad_len = ObfuscationKey::gso_pad_len();

        let mut wire = Vec::new();

        let mut wire_segment = None;

        for chunk in transmit.contents.chunks(segment_size) {
            let obfuscated = self.key.obfuscate_padded(chunk, pad_len)?;

            if chunk.len() == segment_size {
                wire_segment = Some(obfuscated.len());
            }

            wire.extend_from_slice(&obfuscated);
        }

        let wire_segment = wire_segment.filter(|size| *size < wire.len());

        Ok((wire, wire_segment))
    }
}

impl fmt::Debug for ObfuscatedSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObfuscatedSocket")
            .finish_non_exhaustive()
    }
}

fn deobfuscate_into(key: &ObfuscationKey, buf: &mut [u8], meta: &mut RecvMeta) -> bool {
    let total = meta.len;

    if total == 0 {
        return false;
    }

    let stride = if meta.stride == 0 {
        total
    } else {
        meta.stride.min(total)
    };

    let mut plains = Vec::new();

    let mut offset = 0;

    while offset < total {
        let end = (offset + stride).min(total);

        match key.deobfuscate(&buf[offset..end]) {
            Some(plain) => plains.push(plain),

            None => {}
        }

        offset += stride;
    }

    if plains.is_empty() {
        return false;
    }

    let first_len = plains[0].len();

    let uniform = plains
        .iter()
        .rev()
        .skip(1)
        .all(|plain| plain.len() == first_len);

    if !uniform {
        buf[..first_len].copy_from_slice(&plains[0]);

        meta.len = first_len;
        meta.stride = first_len;

        return true;
    }

    let mut out = 0;

    for plain in &plains {
        buf[out..out + plain.len()].copy_from_slice(plain);

        out += plain.len();
    }

    meta.len = out;
    meta.stride = first_len.max(1);

    true
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
        let (obfuscated, segment_size) = self.obfuscate_transmit(transmit)?;

        let wrapped = Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &obfuscated,
            segment_size,
            src_ip: transmit.src_ip,
        };

        self.inner.try_send(&wrapped)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
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

                if deobfuscate_into(&self.key, &mut bufs[index], &mut meta[index]) {
                    if kept != index {
                        let len = meta[index].len;

                        let copied = bufs[index][..len].to_vec();

                        bufs[kept][..len].copy_from_slice(&copied);

                        meta[kept] = meta[index];
                    }

                    kept += 1;
                }
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

        assert!(deobfuscate_into(&key, &mut buf, &mut meta));

        assert_eq!(meta.stride, 40);

        assert_eq!(meta.len, 80);

        assert_eq!(&buf[..40], &[1u8; 40]);

        assert_eq!(&buf[40..80], &[2u8; 40]);
    }
}
