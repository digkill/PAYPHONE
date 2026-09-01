use std::{
    collections::HashMap,
    env, fs,
    path::{Path, PathBuf},
};

use payphone_core::{DEFAULT_PORT, DEFAULT_TCP_PORT};
use payphone_transport::{
    identity::{ServerTlsConfig, default_acme_dir, parse_sans},
    reality::{RealityServerConfig, dest_host, parse_32_bytes, parse_short_ids},
};

#[derive(Clone)]
pub struct ServerSettings {
    pub bind: String,
    pub tcp_bind: Option<String>,
    pub psk: String,
    pub tls: ServerTlsConfig,
    pub auth_key: PathBuf,
    pub dns_upstream: Option<String>,
    pub session_store: Option<PathBuf>,
    pub revoke_file: PathBuf,
    pub reality: Option<RealityServerConfig>,
    pub dev_mode: bool,
}

pub fn load_server_settings() -> Result<ServerSettings, Box<dyn std::error::Error>> {
    let cli = Cli::parse()?;

    if cli.help {
        print_help();
        std::process::exit(0);
    }

    dotenvy::dotenv().ok();

    let mut file = HashMap::new();

    let config_path = cli
        .config
        .clone()
        .or_else(|| env::var_os("PAYPHONE_CONFIG").map(PathBuf::from))
        .or_else(|| {
            let path = PathBuf::from("payphone.toml");
            path.exists().then_some(path)
        });

    if let Some(path) = &config_path {
        if path.exists() {
            file = load_kv_file(path)?;
        } else if cli.config.is_some() {
            return Err(format!("config file not found: {}", path.display()).into());
        }
    }

    let bind = first([
        cli.bind.as_deref(),
        env_opt("PAYPHONE_BIND_ADDR").as_deref(),
        file.get("bind").map(String::as_str),
        file.get("bind_addr").map(String::as_str),
    ])
    .unwrap_or_else(|| format!("127.0.0.1:{DEFAULT_PORT}"));

    let tcp_bind = first([
        cli.tcp_bind.as_deref(),
        env_opt("PAYPHONE_TCP_BIND_ADDR").as_deref(),
        file.get("tcp_bind").map(String::as_str),
        file.get("tcp_bind_addr").map(String::as_str),
    ]);

    let psk = first([
        cli.psk.as_deref(),
        env_opt("PAYPHONE_OBFS_PSK").as_deref(),
        file.get("psk").map(String::as_str),
        file.get("obfs_psk").map(String::as_str),
    ])
    .ok_or("PAYPHONE_OBFS_PSK is not set; pass --psk or put it in .env / payphone.toml")?;

    let mut tls = ServerTlsConfig::default();

    if let Some(path) = first([
        cli.tls_cert.as_deref(),
        env_opt("PAYPHONE_TLS_CERT").as_deref(),
        file.get("tls_cert").map(String::as_str),
    ]) {
        tls.cert_path = PathBuf::from(path);
    }

    if let Some(path) = first([
        cli.tls_key.as_deref(),
        env_opt("PAYPHONE_TLS_KEY").as_deref(),
        file.get("tls_key").map(String::as_str),
    ]) {
        tls.key_path = PathBuf::from(path);
    }

    if let Some(sans) = first([
        cli.tls_san.as_deref(),
        env_opt("PAYPHONE_TLS_SAN").as_deref(),
        file.get("tls_san").map(String::as_str),
    ]) {
        tls.sans = parse_sans(Some(sans));
    }

    if let Some(domain) = first([
        cli.tls_domain.as_deref(),
        env_opt("PAYPHONE_TLS_DOMAIN").as_deref(),
        file.get("tls_domain").map(String::as_str),
    ]) {
        tls.acme_domain = Some(domain.clone());
        if !tls
            .sans
            .iter()
            .any(|name| name.eq_ignore_ascii_case(&domain))
        {
            tls.sans.push(domain);
        }
    }

    if let Some(email) = first([
        cli.acme_email.as_deref(),
        env_opt("PAYPHONE_ACME_EMAIL").as_deref(),
        file.get("acme_email").map(String::as_str),
    ]) {
        tls.acme_email = Some(email);
    }

    if let Some(dir) = first([
        cli.acme_dir.as_deref(),
        env_opt("PAYPHONE_ACME_DIR").as_deref(),
        file.get("acme_dir").map(String::as_str),
    ]) {
        tls.acme_dir = PathBuf::from(dir);
    } else {
        tls.acme_dir = default_acme_dir();
    }

    tls.acme_staging = cli.acme_staging
        || env_flag("PAYPHONE_ACME_STAGING")
        || file
            .get("acme_staging")
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

    let auth_key = PathBuf::from(
        first([
            cli.auth_key.as_deref(),
            env_opt("PAYPHONE_AUTH_KEY").as_deref(),
            file.get("auth_key").map(String::as_str),
        ])
        .unwrap_or_else(|| "auth-keys/subscription-public.key".into()),
    );

    let dns_upstream = first([
        cli.dns_upstream.as_deref(),
        env_opt("PAYPHONE_DNS_UPSTREAM").as_deref(),
        file.get("dns_upstream").map(String::as_str),
    ]);

    let session_store = first([
        cli.session_store.as_deref(),
        env_opt("PAYPHONE_SESSION_STORE").as_deref(),
        file.get("session_store").map(String::as_str),
    ])
    .map(PathBuf::from);

    let revoke_file = PathBuf::from(
        first([
            cli.revoke_file.as_deref(),
            env_opt("PAYPHONE_REVOKE_FILE").as_deref(),
            file.get("revoke_file").map(String::as_str),
        ])
        .unwrap_or_else(|| "auth-keys/revoked-token-ids.txt".into()),
    );

    let mut reality = load_reality(&cli, &file)?;

    if let Some(reality) = reality.as_mut() {
        let dest = dest_host(&reality.dest).ok();
        reality.local_names = tls
            .local_hostnames()
            .into_iter()
            .filter(|name| {
                dest.as_ref()
                    .is_none_or(|host| !name.eq_ignore_ascii_case(host))
            })
            .collect();
    }

    let dev_mode = cli.dev
        || env_flag("PAYPHONE_DEV_MODE")
        || file
            .get("dev")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

    Ok(ServerSettings {
        bind,
        tcp_bind,
        psk,
        tls,
        auth_key,
        dns_upstream,
        session_store,
        revoke_file,
        reality,
        dev_mode,
    })
}

pub fn print_help() {
    eprintln!(
        "\
PAYPHONE server

Usage:
  payphone-server [options]

Options:
      --bind HOST:PORT       UDP listen (default 127.0.0.1:{DEFAULT_PORT})
      --tcp-bind HOST:PORT|off
                             HTTPS front (default same IP, port {DEFAULT_TCP_PORT})
      --psk SECRET           obfuscation secret (or PAYPHONE_OBFS_PSK)
      --tls-cert PATH        PEM or DER certificate (default dev-certs/payphone-cert.der)
      --tls-key PATH         PEM or DER private key
      --tls-san NAMES        comma-separated SANs for a generated self-signed cert
      --tls-domain NAME      Let's Encrypt via TLS-ALPN-01 (needs a public DNS name)
      --acme-email ADDR      ACME account contact (default admin@domain)
      --acme-dir PATH        ACME cache (default /app/state/acme or dev-certs/acme)
      --acme-staging         Let's Encrypt staging (untrusted by browsers)
      --auth-key PATH        Ed25519 public key (default auth-keys/subscription-public.key)
      --dns-upstream HOST:PORT
      --session-store PATH
      --revoke-file PATH     hex token_ids, one per line (default auth-keys/revoked-token-ids.txt)
      --reality on|off       TCP REALITY (default off)
      --reality-dest HOST:PORT
      --reality-private-key PATH|HEX
      --reality-short-id HEX
  -c, --config PATH          optional payphone.toml
      --dev
  -h, --help"
    );
}

#[derive(Default)]
struct Cli {
    help: bool,
    bind: Option<String>,
    tcp_bind: Option<String>,
    psk: Option<String>,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    tls_san: Option<String>,
    tls_domain: Option<String>,
    acme_email: Option<String>,
    acme_dir: Option<String>,
    acme_staging: bool,
    auth_key: Option<String>,
    dns_upstream: Option<String>,
    session_store: Option<String>,
    revoke_file: Option<String>,
    reality: Option<String>,
    reality_dest: Option<String>,
    reality_private_key: Option<String>,
    reality_short_id: Option<String>,
    config: Option<PathBuf>,
    dev: bool,
}

impl Cli {
    fn parse() -> Result<Self, Box<dyn std::error::Error>> {
        let mut cli = Self::default();
        let mut args = env::args().skip(1);

        while let Some(arg) = args.next() {
            if let Some(flag) = arg.strip_prefix("--") {
                if let Some((name, value)) = flag.split_once('=') {
                    cli.set_long(name, value.to_string())?;
                    continue;
                }

                match flag {
                    "help" => cli.help = true,
                    "dev" => cli.dev = true,
                    "acme-staging" => cli.acme_staging = true,
                    name => {
                        let value = args
                            .next()
                            .ok_or_else(|| format!("missing value for --{name}"))?;
                        cli.set_long(name, value)?;
                    }
                }

                continue;
            }

            if arg == "-h" {
                cli.help = true;
                continue;
            }

            if arg == "-c" {
                let value = args.next().ok_or("missing value for -c")?;
                cli.config = Some(PathBuf::from(value));
                continue;
            }

            return Err(format!("unexpected argument {arg}").into());
        }

        Ok(cli)
    }

    fn set_long(&mut self, name: &str, value: String) -> Result<(), Box<dyn std::error::Error>> {
        match name {
            "bind" => self.bind = Some(value),
            "tcp-bind" => self.tcp_bind = Some(value),
            "psk" => self.psk = Some(value),
            "tls-cert" => self.tls_cert = Some(value),
            "tls-key" => self.tls_key = Some(value),
            "tls-san" => self.tls_san = Some(value),
            "tls-domain" => self.tls_domain = Some(value),
            "acme-email" => self.acme_email = Some(value),
            "acme-dir" => self.acme_dir = Some(value),
            "acme-staging" => {
                self.acme_staging = matches!(
                    value.to_ascii_lowercase().as_str(),
                    "1" | "true" | "on" | "yes"
                );
            }
            "auth-key" => self.auth_key = Some(value),
            "dns-upstream" => self.dns_upstream = Some(value),
            "session-store" => self.session_store = Some(value),
            "revoke-file" => self.revoke_file = Some(value),
            "reality" => self.reality = Some(value),
            "reality-dest" => self.reality_dest = Some(value),
            "reality-private-key" => self.reality_private_key = Some(value),
            "reality-short-id" => self.reality_short_id = Some(value),
            "config" => self.config = Some(PathBuf::from(value)),
            other => return Err(format!("unknown option --{other}").into()),
        }

        Ok(())
    }
}

fn load_kv_file(path: &Path) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let text = fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;

    let mut map = HashMap::new();

    for line in text.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };

        let key = key
            .trim()
            .trim_start_matches("payphone_")
            .replace('-', "_")
            .to_ascii_lowercase();

        let value = value
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string();

        map.insert(key, value);
    }

    Ok(map)
}

fn first<const N: usize>(values: [Option<&str>; N]) -> Option<String> {
    values
        .into_iter()
        .flatten()
        .find(|value| !value.is_empty())
        .map(str::to_string)
}

fn env_opt(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.is_empty())
}

fn env_flag(name: &str) -> bool {
    env::var(name)
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "on" | "yes"
            )
        })
        .unwrap_or(false)
}

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn load_reality(
    cli: &Cli,
    file: &HashMap<String, String>,
) -> Result<Option<RealityServerConfig>, Box<dyn std::error::Error>> {
    let enabled = first([
        cli.reality.as_deref(),
        env_opt("PAYPHONE_REALITY").as_deref(),
        file.get("reality").map(String::as_str),
    ]);

    let on = enabled
        .as_deref()
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "on" | "true" | "1" | "yes"
            )
        })
        .unwrap_or(false);

    if !on {
        return Ok(None);
    }

    let dest = first([
        cli.reality_dest.as_deref(),
        env_opt("PAYPHONE_REALITY_DEST").as_deref(),
        file.get("reality_dest").map(String::as_str),
    ])
    .ok_or("PAYPHONE_REALITY=on requires --reality-dest / PAYPHONE_REALITY_DEST")?;

    let key = first([
        cli.reality_private_key.as_deref(),
        env_opt("PAYPHONE_REALITY_PRIVATE_KEY").as_deref(),
        file.get("reality_private_key").map(String::as_str),
    ])
    .unwrap_or_else(|| "auth-keys/reality-private.key".into());

    let private_key = parse_32_bytes(&key)?;

    let short_file = read_trimmed("auth-keys/reality-short-id.txt");

    let short = first([
        cli.reality_short_id.as_deref(),
        env_opt("PAYPHONE_REALITY_SHORT_ID").as_deref(),
        file.get("reality_short_id").map(String::as_str),
        short_file.as_deref(),
    ])
    .ok_or("PAYPHONE_REALITY=on requires --reality-short-id / PAYPHONE_REALITY_SHORT_ID")?;

    let short_ids = parse_short_ids(&short)?;

    Ok(Some(RealityServerConfig::new(
        dest,
        private_key,
        short_ids,
    )?))
}
