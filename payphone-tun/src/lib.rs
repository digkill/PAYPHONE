use std::{io, net::Ipv4Addr, sync::Arc};

use tun_rs::{AsyncDevice, DeviceBuilder};

pub mod routing;

/// IPv4 PAYPHONE network.
///
/// 10.77.0.0/24
pub const PAYPHONE_PREFIX: u8 = 24;

/// MTU туннеля.
///
/// Раньше было 1280 (RFC "безопасно для IPv6"), но это не
/// учитывало реальный бюджет QUIC datagram.
///
/// QUIC гарантирует безопасный MTU только с 1200 байт (RFC 9000);
/// до успешного MTU discovery quinn не поднимает потолок выше
/// этого значения, а после чёрной дыры/потери сбрасывает обратно
/// к нему же. Из этих 1200 quinn резервирует под свой заголовок,
/// AEAD-тег и connection ID ещё ~46 байт (1 flags + 8 CID + 4
/// packet number + 16 tag + 17 DATAGRAM frame overhead) — то есть
/// гарантированный бюджет под один datagram — не больше ~1154.
///
/// PAYPHONE добавляет свои 40 байт заголовков (16 Frame + 24 Data,
/// см. payphone_core::HEADER_SIZE / data::DATA_HEADER_SIZE) поверх
/// самого IP-пакета. При MTU=1280 максимальный кадр (1320 байт)
/// гарантированно превышал безопасный бюджет quinn (~1154) —
/// полагались на то, что MTU discovery успеет поднять потолок до
/// прихода первого крупного пакета. На части сетевых путей это не
/// успевало (или вообще не срабатывало), и `send_datagram_wait`
/// падал с `SendDatagramError::TooLarge` на честном полноразмерном
/// трафике (воспроизведено на реальном деплое).
///
/// 1100 держит худший случай (1100 + 40 = 1140 байт) внутри
/// гарантированного бюджета quinn без всякой зависимости от того,
/// успела ли отработать MTU discovery.
pub const PAYPHONE_MTU: u16 = 1100;

/// IPv4 PAYPHONE server внутри VPN.
///
/// 10.77.0.1
pub const SERVER_TUN_IPV4: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 1);

/// Общий тип TUN device.
///
/// Arc нужен потому, что одновременно
/// будут работать:
///
/// TUN -> QUIC
///
/// и
///
/// QUIC -> TUN.
pub type SharedTun = Arc<AsyncDevice>;

/// Создаёт клиентский TUN.
///
/// `assigned_ipv4` приходит
/// из AllGoodDude / StillGoodDude.
///
/// Например:
///
/// 10.77.0.2
pub fn create_client_tun(assigned_ipv4: [u8; 4], mtu: u16) -> io::Result<SharedTun> {
    let address = Ipv4Addr::new(
        assigned_ipv4[0],
        assigned_ipv4[1],
        assigned_ipv4[2],
        assigned_ipv4[3],
    );

    let builder = DeviceBuilder::new()
        .ipv4(address, PAYPHONE_PREFIX, Some(SERVER_TUN_IPV4))
        .mtu(mtu);

    //
    // На Linux имя можем выбрать сами.
    //
    #[cfg(target_os = "linux")]
    let builder = builder.name("payphone0");

    //
    // На macOS имя вида utunN
    // лучше дать выбрать системе.
    //
    let device = builder.build_async()?;

    Ok(Arc::new(device))
}

/// Создаёт TUN на VPN-сервере.
///
/// Адрес:
///
/// 10.77.0.1/24
pub fn create_server_tun() -> io::Result<SharedTun> {
    let builder = DeviceBuilder::new()
        .ipv4(SERVER_TUN_IPV4, PAYPHONE_PREFIX, None::<Ipv4Addr>)
        .mtu(PAYPHONE_MTU);

    #[cfg(target_os = "linux")]
    let builder = builder.name("payphone0");

    let device = builder.build_async()?;

    Ok(Arc::new(device))
}

/// Извлекает IPv4 destination
/// из настоящего IP packet.
///
/// IPv4 header:
///
/// BYTE 0:
/// version + IHL
///
/// BYTE 16-19:
/// destination IPv4
pub fn ipv4_destination(packet: &[u8]) -> Option<[u8; 4]> {
    if packet.len() < 20 {
        return None;
    }

    //
    // Старшие четыре бита
    // первого byte = IP version.
    //
    let version = packet[0] >> 4;

    if version != 4 {
        return None;
    }

    Some([packet[16], packet[17], packet[18], packet[19]])
}

/// Source IPv4.
///
/// Полезно для проверки
/// клиентского packet.
pub fn ipv4_source(packet: &[u8]) -> Option<[u8; 4]> {
    if packet.len() < 20 {
        return None;
    }

    if packet[0] >> 4 != 4 {
        return None;
    }

    Some([packet[12], packet[13], packet[14], packet[15]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_addresses() {
        let mut packet = [0u8; 20];

        //
        // IPv4 + IHL 5.
        //
        packet[0] = 0x45;

        packet[12..16].copy_from_slice(&[10, 77, 0, 2]);

        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);

        assert_eq!(ipv4_source(&packet), Some([10, 77, 0, 2]));

        assert_eq!(ipv4_destination(&packet), Some([1, 1, 1, 1]));
    }
}
