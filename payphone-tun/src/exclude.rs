//! IPv4 destinations that bypass the full tunnel and keep using the LAN gateway.

use std::{fmt, net::Ipv4Addr, str::FromStr};

/// Upper bound on one exclusion list; each entry is a kernel route.
pub const MAX_EXCLUDED_ROUTES: usize = 4096;

const PAYPHONE_SUBNET: Ipv4Net = Ipv4Net {
    network: Ipv4Addr::new(10, 77, 0, 0),
    prefix: crate::PAYPHONE_PREFIX,
};

const LOOPBACK: Ipv4Net = Ipv4Net {
    network: Ipv4Addr::new(127, 0, 0, 0),
    prefix: 8,
};

/// Shortest prefix that is still more specific than the `/1` tunnel routes.
const MIN_PREFIX: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ipv4Net {
    network: Ipv4Addr,
    prefix: u8,
}

impl Ipv4Net {
    /// Rejects host bits so `192.168.1.5/24` is not silently widened.
    pub fn new(address: Ipv4Addr, prefix: u8) -> Result<Self, String> {
        if prefix > 32 {
            return Err(format!("prefix /{prefix} is out of range 0..=32"));
        }

        let net = Self {
            network: Ipv4Addr::from(u32::from(address) & mask_bits(prefix)),
            prefix,
        };

        if net.network != address {
            return Err(format!("host bits are set; did you mean {net}?"));
        }

        Ok(net)
    }

    pub fn network(&self) -> Ipv4Addr {
        self.network
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    pub fn mask(&self) -> Ipv4Addr {
        Ipv4Addr::from(mask_bits(self.prefix))
    }

    fn first(&self) -> u32 {
        u32::from(self.network)
    }

    fn last(&self) -> u32 {
        self.first() | !mask_bits(self.prefix)
    }

    pub fn contains(&self, address: Ipv4Addr) -> bool {
        u32::from(address) & mask_bits(self.prefix) == self.first()
    }

    pub fn overlaps(&self, other: &Self) -> bool {
        self.first() <= other.last() && other.first() <= self.last()
    }
}

impl fmt::Display for Ipv4Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

impl FromStr for Ipv4Net {
    type Err = String;

    /// `203.0.113.7`, `198.51.100.0/24` or `198.51.100.0/255.255.255.0`.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (text, None),
        };

        let address = address.parse::<Ipv4Addr>().map_err(|_| {
            if address.parse::<std::net::Ipv6Addr>().is_ok() {
                "IPv6 is not supported: all IPv6 is blocked while the VPN is up".to_string()
            } else {
                "not an IPv4 address or CIDR".to_string()
            }
        })?;

        let prefix = match prefix {
            None => 32,
            Some(prefix) if prefix.contains('.') => {
                let mask = prefix
                    .parse::<Ipv4Addr>()
                    .map_err(|_| format!("bad netmask {prefix}"))?;
                prefix_from_mask(mask).ok_or_else(|| format!("netmask {mask} is not contiguous"))?
            }
            Some(prefix) => prefix
                .parse::<u8>()
                .map_err(|_| format!("bad prefix /{prefix}"))?,
        };

        Self::new(address, prefix)
    }
}

#[derive(Debug)]
pub struct ExcludeError {
    pub entry: String,
    pub reason: String,
}

impl fmt::Display for ExcludeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid exclusion \"{}\": {}", self.entry, self.reason)
    }
}

impl std::error::Error for ExcludeError {}

/// Parses, validates and collapses the list: duplicates and networks that
/// sit inside another entry are dropped, so each kernel route is unique.
pub fn parse_exclusions<I, S>(entries: I) -> Result<Vec<Ipv4Net>, ExcludeError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut nets = Vec::new();

    for entry in entries {
        let entry = entry.as_ref().trim();

        let error = |reason: String| ExcludeError {
            entry: entry.to_string(),
            reason,
        };

        let net = entry.parse::<Ipv4Net>().map_err(error)?;

        if net.prefix < MIN_PREFIX {
            return Err(error(format!(
                "/{} would replace the full-tunnel routes; use /{MIN_PREFIX} or longer",
                net.prefix
            )));
        }

        if net.overlaps(&PAYPHONE_SUBNET) {
            return Err(error(format!(
                "overlaps the PAYPHONE subnet {PAYPHONE_SUBNET}"
            )));
        }

        if net.overlaps(&LOOPBACK) {
            return Err(error(format!("overlaps loopback {LOOPBACK}")));
        }

        nets.push(net);
    }

    if nets.len() > MAX_EXCLUDED_ROUTES {
        return Err(ExcludeError {
            entry: format!("{} entries", nets.len()),
            reason: format!("at most {MAX_EXCLUDED_ROUTES} exclusions are supported"),
        });
    }

    // CIDR blocks are either nested or disjoint, so after sorting by start
    // (wider first) a block is redundant iff it ends inside the kept span.
    nets.sort_by_key(|net| (net.first(), net.prefix));

    let mut collapsed: Vec<Ipv4Net> = Vec::with_capacity(nets.len());

    for net in nets {
        if collapsed
            .last()
            .is_some_and(|kept| kept.first() <= net.first() && net.last() <= kept.last())
        {
            continue;
        }

        collapsed.push(net);
    }

    Ok(collapsed)
}

fn mask_bits(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

fn prefix_from_mask(mask: Ipv4Addr) -> Option<u8> {
    let bits = u32::from(mask);
    let prefix = bits.leading_ones() as u8;

    (mask_bits(prefix) == bits).then_some(prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(text: &str) -> Ipv4Net {
        text.parse().unwrap()
    }

    #[test]
    fn parses_address_prefix_and_netmask_forms() {
        assert_eq!(net("203.0.113.7").to_string(), "203.0.113.7/32");
        assert_eq!(net("198.51.100.0/24").to_string(), "198.51.100.0/24");
        assert_eq!(net("198.51.100.0/255.255.255.0"), net("198.51.100.0/24"));
        assert_eq!(net("172.16.0.0/12").mask(), Ipv4Addr::new(255, 240, 0, 0));
    }

    #[test]
    fn rejects_malformed_entries() {
        for bad in [
            "",
            "example.com",
            "1.2.3",
            "1.2.3.4/33",
            "1.2.3.4/x",
            "1.2.3.0/255.0.255.0",
            "192.168.1.5/24",
            "2001:db8::/32",
        ] {
            assert!(bad.parse::<Ipv4Net>().is_err(), "{bad} should fail");
        }

        let error = "192.168.1.5/24".parse::<Ipv4Net>().unwrap_err();
        assert!(error.contains("192.168.1.0/24"), "{error}");

        let error = "2001:db8::1".parse::<Ipv4Net>().unwrap_err();
        assert!(error.contains("IPv6"), "{error}");
    }

    #[test]
    fn rejects_routes_that_would_break_the_tunnel() {
        for bad in [
            "0.0.0.0/0",
            "128.0.0.0/1",
            "10.77.0.1",
            "10.77.5.0/24",
            "10.0.0.0/8",
            "127.0.0.1",
        ] {
            assert!(parse_exclusions([bad]).is_err(), "{bad} should fail");
        }

        let error = parse_exclusions(["ok", "1.1.1.1"]).unwrap_err();
        assert_eq!(error.entry, "ok");
    }

    #[test]
    fn collapses_duplicates_and_nested_blocks() {
        let nets = parse_exclusions([
            " 192.168.1.10 ",
            "192.168.0.0/16",
            "192.168.0.0/16",
            "203.0.113.0/24",
            "203.0.113.128/25",
            "198.51.100.7",
            "203.0.114.0/24",
        ])
        .unwrap();

        let text: Vec<_> = nets.iter().map(ToString::to_string).collect();
        assert_eq!(
            text,
            [
                "192.168.0.0/16",
                "198.51.100.7/32",
                "203.0.113.0/24",
                "203.0.114.0/24"
            ]
        );
    }

    #[test]
    fn enforces_the_route_budget() {
        let many: Vec<_> = (0..=MAX_EXCLUDED_ROUTES)
            .map(|index| format!("100.64.{}.{}", index / 256, index % 256))
            .collect();

        assert!(parse_exclusions(&many).is_err());
        assert_eq!(
            parse_exclusions(&many[..MAX_EXCLUDED_ROUTES])
                .unwrap()
                .len(),
            MAX_EXCLUDED_ROUTES
        );
    }

    #[test]
    fn contains_and_overlap() {
        let lan = net("192.168.0.0/16");
        assert!(lan.contains(Ipv4Addr::new(192, 168, 7, 1)));
        assert!(!lan.contains(Ipv4Addr::new(192, 169, 0, 1)));
        assert!(lan.overlaps(&net("192.168.4.0/24")));
        assert!(!lan.overlaps(&net("192.169.0.0/16")));
    }
}
