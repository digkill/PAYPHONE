use std::{
    env, fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::{SigningKey, VerifyingKey};

use rand_core::{OsRng, TryRngCore};

use payphone_auth::{
    CLIENT_ID_SIZE, SubscriptionClaims, SubscriptionPlan, SubscriptionToken, TOKEN_ID_SIZE,
};

// =============================================================
// PATHS
// =============================================================

//
// Закрытый signing key.
//
// Этот файл:
//
// НИКОГДА
// не отправляется клиенту.
//
// На production он должен находиться
// только на issuer/backend машине.
//
const PRIVATE_KEY_PATH: &str = "auth-keys/subscription-private.key";

//
// Public key.
//
// Его использует PAYPHONE server
// для проверки subscription.token.
//
const PUBLIC_KEY_PATH: &str = "auth-keys/subscription-public.key";

//
// Готовый subscription token.
//
// Этот файл передаётся клиенту.
//
const TOKEN_PATH: &str = "subscription.token";

//
// ID текущего signing key.
//
// Server сейчас тоже регистрирует:
//
// key_id = 1
//
const KEY_ID: u32 = 1;

// =============================================================
// MAIN
// =============================================================

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();

        return Ok(());
    }

    match args[1].as_str() {
        //
        // Генерация Ed25519 keypair.
        //
        "init" => {
            init_keys()?;
        }

        //
        // Выпуск subscription.token.
        //
        //
        // Пример:
        //
        // payphone-token issue 30 pro
        //
        "issue" => {
            if args.len() != 4 {
                println!("Usage:");

                println!("  payphone-token issue <days> <plan>");

                println!();

                println!("Plans:");

                println!("  basic");

                println!("  pro");

                println!("  unlimited");

                return Ok(());
            }

            let days: u64 = args[2]
                .parse()
                .map_err(|_| "days must be a positive integer")?;

            if days == 0 {
                return Err("days must be greater than zero".into());
            }

            let plan = parse_plan(&args[3])?;

            issue_token(days, plan)?;
        }

        //
        // Полный setup одним вызовом:
        //
        // generate keys if necessary
        // +
        // issue token
        //
        //
        // payphone-token setup 30 pro
        //
        "setup" => {
            if args.len() != 4 {
                println!("Usage:");

                println!("  payphone-token setup <days> <plan>");

                return Ok(());
            }

            let days: u64 = args[2]
                .parse()
                .map_err(|_| "days must be a positive integer")?;

            if days == 0 {
                return Err("days must be greater than zero".into());
            }

            let plan = parse_plan(&args[3])?;

            //
            // Если ключей нет —
            // создаём.
            //
            if !Path::new(PRIVATE_KEY_PATH).exists() || !Path::new(PUBLIC_KEY_PATH).exists() {
                init_keys()?;
            }

            issue_token(days, plan)?;
        }

        _ => {
            print_usage();
        }
    }

    Ok(())
}

// =============================================================
// HELP
// =============================================================

fn print_usage() {
    println!("PAYPHONE Subscription Token Tool");

    println!();

    println!("Generate signing keys:");

    println!("  cargo run -p payphone-token -- init");

    println!();

    println!("Issue subscription:");

    println!("  cargo run -p payphone-token -- issue 30 pro");

    println!();

    println!("Generate keys if needed and issue token:");

    println!("  cargo run -p payphone-token -- setup 30 pro");

    println!();

    println!("Plans:");

    println!("  basic");

    println!("  pro");

    println!("  unlimited");
}

// =============================================================
// INIT KEYS
// =============================================================

fn init_keys() -> Result<(), Box<dyn std::error::Error>> {
    //
    // Не перезаписываем существующий
    // private key случайно.
    //
    if Path::new(PRIVATE_KEY_PATH).exists() {
        return Err(format!(
            "{} already exists; refusing to overwrite signing key",
            PRIVATE_KEY_PATH
        )
        .into());
    }

    if Path::new(PUBLIC_KEY_PATH).exists() {
        return Err(format!(
            "{} already exists; refusing to overwrite public key",
            PUBLIC_KEY_PATH
        )
        .into());
    }

    //
    // Создаём папку.
    //
    fs::create_dir_all("auth-keys")?;

    //
    // PAYPHONE auth crate
    // генерирует Ed25519 SigningKey.
    //
    let signing_key = payphone_auth::generate_signing_key()
        .map_err(|error| format!("failed to generate Ed25519 signing key: {:?}", error))?;

    //
    // Получаем public key.
    //
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    //
    // PRIVATE KEY
    //
    // Ed25519 secret:
    //
    // 32 bytes
    //
    fs::write(PRIVATE_KEY_PATH, signing_key.to_bytes())?;

    //
    // PUBLIC KEY
    //
    // Ed25519 public:
    //
    // 32 bytes
    //
    fs::write(PUBLIC_KEY_PATH, verifying_key.to_bytes())?;

    //
    // На Unix/macOS:
    //
    // chmod 600 private key
    //
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(PRIVATE_KEY_PATH, fs::Permissions::from_mode(0o600))?;
    }

    println!("PAYPHONE subscription signing keys created");

    println!();

    println!("PRIVATE:");

    println!("  {}", PRIVATE_KEY_PATH);

    println!();

    println!("PUBLIC:");

    println!("  {}", PUBLIC_KEY_PATH);

    println!();

    println!("IMPORTANT:");

    println!("  private key stays only on token issuer/backend");

    println!("  public key goes to PAYPHONE server");

    Ok(())
}

// =============================================================
// ISSUE TOKEN
// =============================================================

fn issue_token(days: u64, plan: SubscriptionPlan) -> Result<(), Box<dyn std::error::Error>> {
    //
    // Загружаем signing key.
    //
    let signing_key = load_signing_key()?;

    //
    // Текущее Unix time.
    //
    let now = unix_time()?;

    //
    // Переводим дни
    // в секунды.
    //
    let lifetime = days
        .checked_mul(24)
        .and_then(|value| value.checked_mul(60))
        .and_then(|value| value.checked_mul(60))
        .ok_or("subscription lifetime overflow")?;

    let expires_at = now
        .checked_add(lifetime)
        .ok_or("subscription expiry overflow")?;

    //
    // Random token ID.
    //
    let mut token_id = [0u8; TOKEN_ID_SIZE];

    random_bytes(&mut token_id)?;

    //
    // Random client/account ID.
    //
    // Пока issuer сам создаёт client_id.
    //
    // Позже backend будет передавать
    // существующий account UUID.
    //
    let mut client_id = [0u8; CLIENT_ID_SIZE];

    random_bytes(&mut client_id)?;

    //
    // Параметры тарифа.
    //
    let (device_limit, max_mbps) = match plan {
        SubscriptionPlan::Basic => (1, 100),

        SubscriptionPlan::Pro => (5, 500),

        SubscriptionPlan::Unlimited => {
            //
            // 255 пока означает
            // практически unlimited devices.
            //
            // max_mbps = 0
            // означает отсутствие
            // тарифного bandwidth limit.
            //
            (255, 0)
        }
    };

    //
    // Создаём claims.
    //
    let claims = SubscriptionClaims {
        key_id: KEY_ID,

        token_id,

        client_id,

        issued_at: now,

        not_before: now,

        expires_at,

        plan,

        device_limit,

        max_mbps,
    };

    //
    // Ed25519:
    //
    // claims
    //   ↓
    // signature
    //   ↓
    // SubscriptionToken
    //
    let token = SubscriptionToken::sign(claims, &signing_key);

    //
    // Token -> 135 bytes.
    //
    let encoded = token.encode();

    //
    // Записываем файл,
    // который будет использовать клиент.
    //
    fs::write(TOKEN_PATH, &encoded)?;

    //
    // Проверяем размер.
    //
    println!("PAYPHONE subscription token issued");

    println!();

    println!("File:");

    println!("  {}", TOKEN_PATH);

    println!();

    println!("Size:");

    println!("  {} bytes", encoded.len());

    println!();

    println!("Key ID:");

    println!("  {}", KEY_ID);

    println!();

    println!("Plan:");

    println!("  {:?}", plan);

    println!();

    println!("Device limit:");

    println!("  {}", device_limit);

    println!();

    println!("Max Mbps:");

    if max_mbps == 0 {
        println!("  unlimited");
    } else {
        println!("  {}", max_mbps);
    }

    println!();

    println!("Issued at:");

    println!("  {}", now);

    println!();

    println!("Expires at:");

    println!("  {}", expires_at);

    println!();

    print!("Token ID: ");

    print_hex(&token_id);

    println!();

    print!("Client ID: ");

    print_hex(&client_id);

    println!();

    println!();

    println!("Client can now use:");

    println!("  {}", TOKEN_PATH);

    Ok(())
}

// =============================================================
// LOAD PRIVATE KEY
// =============================================================

fn load_signing_key() -> Result<SigningKey, Box<dyn std::error::Error>> {
    let bytes = fs::read(PRIVATE_KEY_PATH).map_err(|error| {
        format!(
            "cannot read {}: {}. Run `cargo run -p payphone-token -- init` first",
            PRIVATE_KEY_PATH, error
        )
    })?;

    //
    // Ed25519 signing secret
    // обязан быть 32 bytes.
    //
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "subscription private key must be exactly 32 bytes")?;

    Ok(SigningKey::from_bytes(&array))
}

// =============================================================
// PLAN
// =============================================================

fn parse_plan(value: &str) -> Result<SubscriptionPlan, Box<dyn std::error::Error>> {
    match value.to_ascii_lowercase().as_str() {
        "basic" => Ok(SubscriptionPlan::Basic),

        "pro" => Ok(SubscriptionPlan::Pro),

        "unlimited" => Ok(SubscriptionPlan::Unlimited),

        _ => Err(format!("unknown subscription plan: {}", value).into()),
    }
}

// =============================================================
// RANDOM
// =============================================================

fn random_bytes(destination: &mut [u8]) -> Result<(), Box<dyn std::error::Error>> {
    OsRng
        .try_fill_bytes(destination)
        .map_err(|error| format!("OS random generator failed: {:?}", error))?;

    Ok(())
}

// =============================================================
// UNIX TIME
// =============================================================

fn unix_time() -> Result<u64, Box<dyn std::error::Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    Ok(now)
}

// =============================================================
// HEX OUTPUT
// =============================================================

fn print_hex(bytes: &[u8]) {
    for byte in bytes {
        print!("{:02x}", byte);
    }
}
