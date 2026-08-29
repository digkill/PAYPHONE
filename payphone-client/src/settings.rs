use std::{
    collections::HashMap,
    env, fs,
    path::{Path, PathBuf},
};

use payphone_core::{DEFAULT_PORT, DEFAULT_TCP_PORT};
use payphone_transport::identity::ClientTlsConfig;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Quic,
    Tls,
}

#[derive(Clone)]
pub struct ClientSettings {
    pub server: String,
    pub tcp_server: Option<String>,
    pub transport: TransportKind,
    pub psk: String,
    pub token: PathBuf,
    pub session: PathBuf,
    pub tls: ClientTlsConfig,
    pub dev_mode: bool,
}

pub fn load_client_settings() -> Result<ClientSettings, Box<dyn std::error::Error>> {
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
        .or_else(default_config_path);

    if let Some(path) = &config_path {
        if path.exists() {
            file = load_kv_file(path)?;
        } else if cli.config.is_some() {
            return Err(format!("config file not found: {}", path.display()).into());
        }
    }

    let server = first([
        cli.server.as_deref(),
        env_opt("PAYPHONE_SERVER_ADDR").as_deref(),
        file.get("server").map(String::as_str),
        file.get("server_addr").map(String::as_str),
    ])
    .unwrap_or_else(|| format!("127.0.0.1:{DEFAULT_PORT}"));

    let tcp_server = first([
        cli.tcp_server.as_deref(),
        env_opt("PAYPHONE_TCP_SERVER_ADDR").as_deref(),
        file.get("tcp_server").map(String::as_str),
    ]);

    let transport = parse_transport(&first([
        cli.transport.as_deref(),
        env_opt("PAYPHONE_TRANSPORT").as_deref(),
        file.get("transport").map(String::as_str),
    ])
    .unwrap_or_else(|| "quic".into()))?;

    let psk = first([
        cli.psk.as_deref(),
        env_opt("PAYPHONE_OBFS_PSK").as_deref(),
        file.get("psk").map(String::as_str),
        file.get("obfs_psk").map(String::as_str),
    ])
    .ok_or(
        "PAYPHONE_OBFS_PSK is not set; pass --psk or put it in .env / payphone.toml",
    )?;

    let token = PathBuf::from(
        first([
            cli.token.as_deref(),
            env_opt("PAYPHONE_TOKEN").as_deref(),
            file.get("token").map(String::as_str),
        ])
        .unwrap_or_else(|| "subscription.token".into()),
    );

    let session = PathBuf::from(
        first([
            cli.session.as_deref(),
            env_opt("PAYPHONE_SESSION_FILE").as_deref(),
            file.get("session").map(String::as_str),
        ])
        .unwrap_or_else(|| ".payphone-session".into()),
    );

    let mut tls = ClientTlsConfig::default();

    if let Some(name) = first([
        cli.sni.as_deref(),
        env_opt("PAYPHONE_SERVER_NAME").as_deref(),
        file.get("sni").map(String::as_str),
        file.get("server_name").map(String::as_str),
    ]) {
        tls.server_name = name;
    }

    if let Some(path) = first([
        cli.tls_pin.as_deref(),
        env_opt("PAYPHONE_TLS_PIN").as_deref(),
        env_opt("PAYPHONE_TLS_CERT").as_deref(),
        file.get("tls_pin").map(String::as_str),
        file.get("tls_cert").map(String::as_str),
    ]) {
        tls.pin_path = PathBuf::from(path);
    }

    if let Some(ca) = first([
        cli.tls_ca.as_deref(),
        env_opt("PAYPHONE_TLS_CA").as_deref(),
        file.get("tls_ca").map(String::as_str),
    ]) {
        tls.use_webpki = matches!(
            ca.to_ascii_lowercase().as_str(),
            "system" | "webpki" | "public" | "1" | "true"
        );
    }

    let dev_mode = cli.dev
        || env_flag("PAYPHONE_DEV_MODE")
        || file_flag(&file, "dev")
        || file_flag(&file, "dev_mode");

    Ok(ClientSettings {
        server,
        tcp_server,
        transport,
        psk,
        token,
        session,
        tls,
        dev_mode,
    })
}

pub fn print_help() {
    eprintln!(
        "\
PAYPHONE client

Usage:
  payphone-client [options]

Options:
  -s, --server HOST:PORT   VPN server (default 127.0.0.1:{DEFAULT_PORT})
      --tcp-server HOST:PORT
                           HTTPS front (default: same host, port {DEFAULT_TCP_PORT} if UDP is {DEFAULT_PORT})
      --transport quic|tls
  -t, --token PATH         subscription token (default subscription.token)
      --session PATH       encrypted resume file (default .payphone-session)
      --psk SECRET         obfuscation secret (or PAYPHONE_OBFS_PSK)
      --sni NAME           TLS server name (default localhost)
      --tls-pin PATH       pinned certificate (default dev-certs/payphone-cert.der)
      --tls-ca pin|system  pin a file, or trust public CAs (Let's Encrypt)
  -c, --config PATH        optional payphone.toml (also PAYPHONE_CONFIG)
      --dev                log raw UDP datagrams
  -h, --help

Env vars and .env still work. CLI flags win over them. A payphone.toml
next to the binary is loaded if present (`server`, `psk`, `sni`, ...)."
    );
}

#[derive(Default)]
struct Cli {
    help: bool,
    server: Option<String>,
    tcp_server: Option<String>,
    transport: Option<String>,
    psk: Option<String>,
    token: Option<String>,
    session: Option<String>,
    sni: Option<String>,
    tls_pin: Option<String>,
    tls_ca: Option<String>,
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
                    cli.set_long(name, Some(value.to_string()))?;
                    continue;
                }

                match flag {
                    "help" => cli.help = true,
                    "dev" => cli.dev = true,
                    name => {
                        let value = args.next().ok_or_else(|| format!("missing value for --{name}"))?;
                        cli.set_long(name, Some(value))?;
                    }
                }

                continue;
            }

            if let Some(flags) = arg.strip_prefix('-') {
                for (index, ch) in flags.chars().enumerate() {
                    match ch {
                        'h' => cli.help = true,
                        's' | 't' | 'c' => {
                            if index != flags.chars().count() - 1 {
                                return Err("short option that takes a value must be last".into());
                            }
                            let value = args
                                .next()
                                .ok_or_else(|| format!("missing value for -{ch}"))?;
                            match ch {
                                's' => cli.server = Some(value),
                                't' => cli.token = Some(value),
                                'c' => cli.config = Some(PathBuf::from(value)),
                                _ => {}
                            }
                        }
                        _ => return Err(format!("unknown option -{ch}").into()),
                    }
                }

                continue;
            }

            return Err(format!("unexpected argument {arg}").into());
        }

        Ok(cli)
    }

    fn set_long(&mut self, name: &str, value: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
        let value = value.ok_or_else(|| format!("missing value for --{name}"))?;

        match name {
            "server" => self.server = Some(value),
            "tcp-server" => self.tcp_server = Some(value),
            "transport" => self.transport = Some(value),
            "psk" => self.psk = Some(value),
            "token" => self.token = Some(value),
            "session" => self.session = Some(value),
            "sni" => self.sni = Some(value),
            "tls-pin" => self.tls_pin = Some(value),
            "tls-ca" => self.tls_ca = Some(value),
            "config" => self.config = Some(PathBuf::from(value)),
            other => return Err(format!("unknown option --{other}").into()),
        }

        Ok(())
    }
}

pub fn load_kv_file(path: &Path) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
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

fn default_config_path() -> Option<PathBuf> {
    let path = PathBuf::from("payphone.toml");

    path.exists().then_some(path)
}

fn parse_transport(value: &str) -> Result<TransportKind, Box<dyn std::error::Error>> {
    match value.to_ascii_lowercase().as_str() {
        "quic" | "udp" => Ok(TransportKind::Quic),
        "tls" | "https" | "tcp" => Ok(TransportKind::Tls),
        other => Err(format!("unknown transport {other}; use quic or tls").into()),
    }
}

fn first<const N: usize>(values: [Option<&str>; N]) -> Option<String> {
    values.into_iter().flatten().find(|value| !value.is_empty()).map(str::to_string)
}

fn env_opt(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.is_empty())
}

fn env_flag(name: &str) -> bool {
    env::var(name)
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn file_flag(file: &HashMap<String, String>, key: &str) -> bool {
    file.get(key)
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}
