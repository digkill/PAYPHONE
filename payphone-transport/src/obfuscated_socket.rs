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
// GSO/GRO (multi-datagram batching) намеренно не поддерживается:
// max_transmit_segments/max_receive_segments всегда 1, так что
// каждый Transmit/RecvMeta описывает ровно одну датаграмму. Это
// упрощает обфускацию ценой части производительности batched I/O —
// приемлемо для dev-прототипа уровня PAYPHONE.
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
}

impl fmt::Debug for ObfuscatedSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObfuscatedSocket")
            .finish_non_exhaustive()
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
        let obfuscated = self.key.obfuscate(transmit.contents)?;

        let wrapped = Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &obfuscated,
            segment_size: None,
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

            //
            // max_receive_segments() == 1, поэтому bufs[0]/meta[0] —
            // единственная релевантная запись.
            //
            let raw_len = meta[0].len;

            //
            // Неудачная деобфускация (неверный key/passphrase) НЕ
            // отличима здесь от валидного пакета неправильной
            // длины — deobfuscate() возвращает None только для
            // данных короче SALT_LEN. При неверном ключе пакет
            // всё равно дойдёт до quinn как мусор и будет отброшен
            // уже там, молча. В dev_mode логируем сырое поступление,
            // чтобы понять, доходят ли пакеты клиента до сервера.
            //
            if self.dev_mode {
                eprintln!(
                    "PAYPHONE: raw datagram {} bytes from {}",
                    raw_len, meta[0].addr
                );
            }

            match self.key.deobfuscate(&bufs[0][..raw_len]) {
                Some(plain) => {
                    bufs[0][..plain.len()].copy_from_slice(&plain);

                    meta[0].len = plain.len();
                    meta[0].stride = plain.len();

                    return Poll::Ready(Ok(1));
                }

                //
                // Слишком короткий пакет, чтобы быть нашим —
                // тихо отбрасываем (шум/probe) и ждём следующий,
                // не отдавая мусор quinn.
                //
                None => continue,
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
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }
}
