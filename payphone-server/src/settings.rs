use std::{
    collections::HashMap,
    env, fs,
    path::{Path, PathBuf},
};

use payphone_core::{DEFAULT_PORT, DEFAULT_TCP_PORT};
use payphone_transport::identity::{ServerTlsConfig, parse_sans};

#[derive(Clone)]
pub struct ServerSettings {
    pub bind: String,
    pub tcp_bind: Option<String>,
    pub psk: String,
    pub tls: ServerTlsConfig,
    pub auth_key: PathBuf,
    pub dns_upstream: Option<String>,
    pub session_store: Option<PathBuf>,
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
    .ok_or(
        "PAYPHONE_OBFS_PSK is not set; pass --psk or put it in .env / payphone.toml",
    )?;

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

    let dev_mode = cli.dev
        || env_flag("PAYPHONE_DEV_MODE")
        || file.get("dev").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false);

    Ok(ServerSettings {
        bind,
        tcp_bind,
        psk,
        tls,
        auth_key,
        dns_upstream,
        session_store,
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
      --auth-key PATH        Ed25519 public key (default auth-keys/subscription-public.key)
      --dns-upstream HOST:PORT
      --session-store PATH
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
    auth_key: Option<String>,
    dns_upstream: Option<String>,
    session_store: Option<String>,
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
                    name => {
                        let value = args.next().ok_or_else(|| format!("missing value for --{name}"))?;
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
            "auth-key" => self.auth_key = Some(value),
            "dns-upstream" => self.dns_upstream = Some(value),
            "session-store" => self.session_store = Some(value),
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

        let value = value.trim().trim_matches('"').trim_matches('\'').to_string();

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
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}
