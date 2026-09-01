use std::{
    collections::HashMap,
    env, fs,
    path::{Path, PathBuf},
};

use payphone_core::{DEFAULT_PORT, DEFAULT_TCP_PORT};
use payphone_transport::{
    identity::ClientTlsConfig,
    reality::{RealityClientConfig, dest_host, parse_32_bytes, parse_short_id},
};

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
    pub kill_switch: bool,
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

    let transport = parse_transport(
        &first([
            cli.transport.as_deref(),
            env_opt("PAYPHONE_TRANSPORT").as_deref(),
            file.get("transport").map(String::as_str),
        ])
        .unwrap_or_else(|| "quic".into()),
    )?;

    let psk = first([
        cli.psk.as_deref(),
        env_opt("PAYPHONE_OBFS_PSK").as_deref(),
        file.get("psk").map(String::as_str),
        file.get("obfs_psk").map(String::as_str),
    ])
    .ok_or("PAYPHONE_OBFS_PSK is not set; pass --psk or put it in .env / payphone.toml")?;

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

    let sni_explicit = first([
        cli.sni.as_deref(),
        env_opt("PAYPHONE_SERVER_NAME").as_deref(),
        file.get("sni").map(String::as_str),
        file.get("server_name").map(String::as_str),
    ]);

    if let Some(name) = sni_explicit {
        tls.server_name = name;
    } else if let Some(host) = payphone_transport::identity::hostname_from_addr(&server) {
        if payphone_transport::identity::looks_like_public_dns_name(&host) {
            tls.server_name = host;
        }
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

    let tls_ca = first([
        cli.tls_ca.as_deref(),
        env_opt("PAYPHONE_TLS_CA").as_deref(),
        file.get("tls_ca").map(String::as_str),
    ]);

    if let Some(ca) = &tls_ca {
        tls.use_webpki = matches!(
            ca.to_ascii_lowercase().as_str(),
            "system" | "webpki" | "public" | "1" | "true"
        );
    } else if payphone_transport::identity::looks_like_public_dns_name(&tls.server_name) {
        tls.use_webpki = true;
    }

    if let Some(pubkey) = first([
        cli.reality_pubkey.as_deref(),
        env_opt("PAYPHONE_REALITY_PUBLIC_KEY").as_deref(),
        file.get("reality_public_key").map(String::as_str),
        file.get("reality_pubkey").map(String::as_str),
    ]) {
        let short = first([
            cli.reality_short_id.as_deref(),
            env_opt("PAYPHONE_REALITY_SHORT_ID").as_deref(),
            file.get("reality_short_id").map(String::as_str),
        ])
        .ok_or("REALITY public key is set; pass --reality-short-id / PAYPHONE_REALITY_SHORT_ID")?;

        let server_name = first([
            cli.reality_sni.as_deref(),
            env_opt("PAYPHONE_REALITY_SNI").as_deref(),
            file.get("reality_sni").map(String::as_str),
            cli.sni.as_deref(),
            env_opt("PAYPHONE_SERVER_NAME").as_deref(),
        ])
        .unwrap_or_else(|| tls.server_name.clone());

        let server_name = dest_host(&server_name).unwrap_or(server_name);

        tls.server_name = server_name.clone();
        tls.reality = Some(RealityClientConfig {
            public_key: parse_32_bytes(&pubkey)?,
            short_id: parse_short_id(&short)?,
            server_name,
        });
    }

    let kill_switch = cli.kill_switch
        || env_flag("PAYPHONE_KILL_SWITCH")
        || file_flag(&file, "kill_switch")
        || file_flag(&file, "killswitch");

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
        kill_switch,
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
      --sni NAME           TLS server name (default: hostname from --server, else localhost)
      --tls-pin PATH       pinned certificate (default dev-certs/payphone-cert.der)
      --tls-ca pin|system  pin a file, or trust public CAs (Let's Encrypt).
                           Default system when SNI looks like a public DNS name.
      --reality-pubkey HEX|PATH
      --reality-short-id HEX
      --reality-sni NAME   ClientHello SNI (dest hostname, not the pin SAN)
      --kill-switch        no Internet unless the VPN is up (default off)
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
    reality_pubkey: Option<String>,
    reality_short_id: Option<String>,
    reality_sni: Option<String>,
    config: Option<PathBuf>,
    dev: bool,
    kill_switch: bool,
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
                    "kill-switch" => cli.kill_switch = true,
                    name => {
                        let value = args
                            .next()
                            .ok_or_else(|| format!("missing value for --{name}"))?;
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

    fn set_long(
        &mut self,
        name: &str,
        value: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
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
            "reality-pubkey" | "reality-public-key" => self.reality_pubkey = Some(value),
            "reality-short-id" => self.reality_short_id = Some(value),
            "reality-sni" => self.reality_sni = Some(value),
            "kill-switch" => {
                self.kill_switch = parse_bool_flag(&value)?;
            }
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

        let value = value
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string();

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
        .ok()
        .and_then(|value| parse_bool_flag(&value).ok())
        .unwrap_or(false)
}

fn file_flag(file: &HashMap<String, String>, key: &str) -> bool {
    file.get(key)
        .and_then(|value| parse_bool_flag(value).ok())
        .unwrap_or(false)
}

fn parse_bool_flag(value: &str) -> Result<bool, Box<dyn std::error::Error>> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "on" | "yes" => Ok(true),
        "0" | "false" | "off" | "no" => Ok(false),
        other => Err(format!("expected on/off, got {other}").into()),
    }
}
