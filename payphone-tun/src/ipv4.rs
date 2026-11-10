//! IPv4 path-MTU handling before encapsulation. No PAYPHONE wire changes.

use std::net::Ipv4Addr;

pub enum MtuResult {
    Fragments(Vec<Vec<u8>>),
    FragmentationNeeded(Vec<u8>),
    Drop,
}

pub fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn finish_header(packet: &mut [u8]) {
    let len = packet.len() as u16;
    packet[2..4].copy_from_slice(&len.to_be_bytes());
    packet[10..12].fill(0);
    let header_len = usize::from(packet[0] & 15) * 4;
    let sum = checksum(&packet[..header_len]);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
}

fn copied_options(options: &[u8]) -> Option<Vec<u8>> {
    let mut copied = Vec::new();
    let mut offset = 0;
    while offset < options.len() {
        let kind = options[offset];
        if kind == 0 {
            break;
        }
        if kind == 1 {
            offset += 1;
            continue;
        }
        let len = usize::from(*options.get(offset + 1)?);
        if len < 2 {
            return None;
        }
        let option = options.get(offset..offset + len)?;
        if kind & 0x80 != 0 {
            copied.extend_from_slice(option);
        }
        offset += len;
    }
    while copied.len() % 4 != 0 {
        copied.push(0);
    }
    Some(copied)
}

/// Fragment DF=0 packets, or report the next-hop MTU with ICMP type 3/code 4.
/// ICMP errors are suppressed for noninitial fragments and ICMP error packets.
pub fn fit_packet(packet: &[u8], mtu: u16, router: Ipv4Addr) -> MtuResult {
    if !super::valid_ipv4_packet(packet) {
        return MtuResult::Drop;
    }
    if packet.len() <= usize::from(mtu) {
        return MtuResult::Fragments(vec![packet.to_vec()]);
    }
    let header_len = usize::from(packet[0] & 15) * 4;
    let flags_offset = u16::from_be_bytes([packet[6], packet[7]]);
    let base_offset = usize::from(flags_offset & 0x1fff) * 8;
    if flags_offset & 0x4000 != 0 {
        let source = &packet[12..16];
        let destination = &packet[16..20];
        let invalid_address = |ip: &[u8]| ip[0] == 0 || ip[0] >= 224 || ip == [255; 4];
        if base_offset != 0
            || invalid_address(source)
            || invalid_address(destination)
            || (packet[9] == 1
                && packet
                    .get(header_len)
                    .is_some_and(|t| matches!(t, 3 | 4 | 5 | 11 | 12)))
        {
            return MtuResult::Drop;
        }
        let quote_len = (header_len + 8).min(packet.len());
        let mut reply = vec![0; 28 + quote_len];
        reply[0] = 0x45;
        reply[8] = 64;
        reply[9] = 1;
        reply[12..16].copy_from_slice(&router.octets());
        reply[16..20].copy_from_slice(source);
        reply[20] = 3;
        reply[21] = 4;
        reply[26..28].copy_from_slice(&mtu.to_be_bytes());
        reply[28..].copy_from_slice(&packet[..quote_len]);
        let sum = checksum(&reply[20..]);
        reply[22..24].copy_from_slice(&sum.to_be_bytes());
        finish_header(&mut reply);
        return MtuResult::FragmentationNeeded(reply);
    }
    let Some(options) = copied_options(&packet[20..header_len]) else {
        return MtuResult::Drop;
    };
    let payload = &packet[header_len..];
    if flags_offset & 0x2000 != 0 && payload.len() % 8 != 0 {
        return MtuResult::Drop;
    }
    if base_offset + payload.len() > 65535 - header_len {
        return MtuResult::Drop;
    }
    let mut fragments = Vec::new();
    let mut offset = 0;
    while offset < payload.len() {
        let first = base_offset == 0 && offset == 0;
        let mut fragment = packet[..20].to_vec();
        fragment.extend_from_slice(if first {
            &packet[20..header_len]
        } else {
            &options
        });
        let size = (usize::from(mtu).saturating_sub(fragment.len()) / 8) * 8;
        if size < 8 {
            return MtuResult::Drop;
        }
        let end = (offset + size).min(payload.len());
        let more = end < payload.len() || flags_offset & 0x2000 != 0;
        let fragment_offset = ((base_offset + offset) / 8) as u16 | if more { 0x2000 } else { 0 };
        fragment[0] = 0x40 | (fragment.len() / 4) as u8;
        fragment[6..8].copy_from_slice(&fragment_offset.to_be_bytes());
        fragment.extend_from_slice(&payload[offset..end]);
        finish_header(&mut fragment);
        fragments.push(fragment);
        offset = end;
    }
    MtuResult::Fragments(fragments)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(df: bool) -> Vec<u8> {
        let mut p = vec![0xAB; 1450];
        p[..20].fill(0);
        p[0] = 0x45;
        p[4..6].copy_from_slice(&123u16.to_be_bytes());
        p[6] = if df { 0x40 } else { 0 };
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&[1, 1, 1, 1]);
        p[16..20].copy_from_slice(&[10, 77, 0, 2]);
        finish_header(&mut p);
        p
    }

    #[test]
    fn fragments_reassemble_without_corruption() {
        let p = packet(false);
        let MtuResult::Fragments(parts) = fit_packet(&p, 1100, Ipv4Addr::LOCALHOST) else {
            panic!()
        };
        assert_eq!(parts.len(), 2);
        let mut payload = Vec::new();
        for (i, part) in parts.iter().enumerate() {
            assert!(part.len() <= 1100);
            assert_eq!(checksum(&part[..20]), 0);
            let flags = u16::from_be_bytes([part[6], part[7]]);
            assert_eq!(usize::from(flags & 0x1fff) * 8, payload.len());
            assert_eq!(flags & 0x2000 != 0, i + 1 < parts.len());
            assert_eq!(&part[4..6], &p[4..6]);
            payload.extend_from_slice(&part[20..]);
        }
        assert_eq!(payload, p[20..]);
    }

    #[test]
    fn df_reports_mtu_and_quotes_original_packet() {
        let p = packet(true);
        let MtuResult::FragmentationNeeded(reply) =
            fit_packet(&p, 1100, Ipv4Addr::new(10, 77, 0, 1))
        else {
            panic!()
        };
        assert_eq!(&reply[20..22], &[3, 4]);
        assert_eq!(&reply[26..28], &1100u16.to_be_bytes());
        assert_eq!(&reply[16..20], &p[12..16]);
        assert_eq!(&reply[28..], &p[..28]);
        assert_eq!(checksum(&reply[..20]), 0);
        assert_eq!(checksum(&reply[20..]), 0);
    }

    #[test]
    fn icmp_errors_and_later_fragments_do_not_trigger_icmp() {
        let mut p = packet(true);
        p[9] = 1;
        p[20] = 3;
        assert!(matches!(
            fit_packet(&p, 1100, Ipv4Addr::LOCALHOST),
            MtuResult::Drop
        ));
        p[9] = 17;
        p[7] = 1;
        assert!(matches!(
            fit_packet(&p, 1100, Ipv4Addr::LOCALHOST),
            MtuResult::Drop
        ));
    }

    #[test]
    fn refragmentation_copies_only_required_options_and_preserves_offset() {
        let mut p = packet(false);
        p.splice(20..20, [0x82, 4, 1, 2, 0x02, 4, 3, 4]);
        p[0] = 0x47;
        finish_header(&mut p);
        let MtuResult::Fragments(parts) = fit_packet(&p, 1100, Ipv4Addr::LOCALHOST) else {
            panic!()
        };
        assert_eq!(parts[0][0] & 15, 7);
        assert_eq!(parts[1][0] & 15, 6);
        assert_eq!(&parts[1][20..24], &[0x82, 4, 1, 2]);
        let MtuResult::Fragments(smaller) = fit_packet(&parts[1], 200, Ipv4Addr::LOCALHOST) else {
            panic!()
        };
        assert_eq!(smaller[0][6..8], [parts[1][6] | 0x20, parts[1][7]]);
        assert!(smaller.iter().all(|part| checksum(&part[..24]) == 0));
    }
}
