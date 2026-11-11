use std::{
    fs,
    net::{Ipv4Addr, ToSocketAddrs},
    path::Path,
    str::FromStr,
};

use payphone_tun::exclude::{Ipv4Net, parse_exclusions};
use serde::Deserialize;

pub const DEFAULT_EXCLUDE_FILE: &str = "payphone-exclude.json";

/// `exclude` accepts IPv4 networks and DNS names. Names resolve to IPv4
/// routes once at startup; an apex domain also includes its `www` hostname.
/// JSON has no comments, so a free-form `comment` field is accepted and ignored.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExcludeFile {
    exclude: Vec<String>,

    #[serde(default)]
    #[allow(dead_code)]
    comment: Option<serde_json::Value>,
}

pub fn load(path: &Path) -> Result<Vec<Ipv4Net>, Box<dyn std::error::Error>> {
    let text = fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;

    parse(&text).map_err(|error| format!("{}: {error}", path.display()).into())
}

fn parse(text: &str) -> Result<Vec<Ipv4Net>, Box<dyn std::error::Error>> {
    let file: ExcludeFile = serde_json::from_str(text)?;
    let mut routes = Vec::new();

    for entry in &file.exclude {
        if Ipv4Net::from_str(entry).is_ok() {
            routes.push(entry.clone());
            continue;
        }

        let domain = entry.trim().trim_end_matches('.');
        if entry.contains('/') || !valid_domain(domain) {
            return Err(format!(
                "invalid exclusion \"{entry}\": expected an IPv4 address, CIDR, or DNS name"
            )
            .into());
        }

        let mut names = vec![domain.to_string()];
        if domain.split('.').count() == 2 && !domain.starts_with("www.") {
            names.push(format!("www.{domain}"));
        }

        let mut domain_addresses = Vec::new();
        let mut last_resolution_error = None;
        for name in names {
            match (name.as_str(), 0).to_socket_addrs() {
                Ok(addresses) => {
                    for address in addresses {
                        if let std::net::SocketAddr::V4(address) = address {
                            domain_addresses.push(format!("{}/32", address.ip()));
                        }
                    }
                }
                Err(error) => last_resolution_error = Some((name, error)),
            }
        }

        if domain_addresses.is_empty() {
            if let Some((name, error)) = last_resolution_error {
                return Err(format!("cannot resolve exclusion domain {name}: {error}").into());
            }
            return Err(format!("exclusion domain {domain} has no IPv4 address").into());
        }
        routes.extend(domain_addresses);
    }

    Ok(parse_exclusions(&routes)?)
}

fn valid_domain(domain: &str) -> bool {
    if domain.len() > 253 || domain.is_empty() || domain.parse::<Ipv4Addr>().is_ok() {
        return false;
    }

    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && label.as_bytes()[0].is_ascii_alphanumeric()
            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_documented_format() {
        let nets = parse(
            r#"{
                "comment": "office and bank",
                "exclude": ["192.168.0.0/16", "203.0.113.7", "198.51.100.0/255.255.255.0"]
            }"#,
        )
        .unwrap();

        let text: Vec<_> = nets.iter().map(ToString::to_string).collect();
        assert_eq!(
            text,
            ["192.168.0.0/16", "198.51.100.0/24", "203.0.113.7/32"]
        );
    }

    #[test]
    fn empty_list_is_valid() {
        assert!(parse(r#"{"exclude": []}"#).unwrap().is_empty());
    }

    #[test]
    fn rejects_bad_shape_and_bad_entries() {
        for bad in [
            "",
            "[]",
            r#"{"exclude": "1.1.1.1"}"#,
            r#"{"exclude": [1]}"#,
            r#"{"exlude": ["1.1.1.1"]}"#,
            r#"{"exclude": ["1.1.1.1"], "extra": true}"#,
            r#"{"exclude": ["10.77.0.0/24"]}"#,
        ] {
            assert!(parse(bad).is_err(), "{bad} should fail");
        }

        let error = parse(r#"{"exclude": ["1.1.1.1", "nope"]}"#)
            .unwrap_err()
            .to_string();
        assert!(error.contains("\"nope\""), "{error}");
    }
}
