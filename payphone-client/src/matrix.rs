//
// Чисто косметика: зелёная "цифровой дождь"-заставка при старте
// клиента, зелёные статусы подключения и живой индикатор потока
// пакетов в открытом туннеле. Никак не влияет на протокол/логику —
// только терминальный вывод.
//

use std::{
    io::{self, Write},
    time::{Duration, Instant},
};

const RESET: &str = "\x1b[0m";
const GREEN: &str = "\x1b[32m";
const BRIGHT_GREEN: &str = "\x1b[92m";
const BOLD_GREEN: &str = "\x1b[1;32m";
const DIM_GREEN: &str = "\x1b[2;32m";

const RAIN_CHARS: &[char] = &[
    'ﾊ', 'ﾐ', 'ﾋ', 'ｰ', 'ｳ', 'ｼ', 'ﾅ', 'ﾓ', 'ﾆ', 'ｻ', 'ﾜ', 'ﾂ', 'ｵ', 'ﾘ', 'ｱ', 'ﾎ', 'ﾃ', 'ﾏ', 'ｹ',
    'ﾒ', 'ｴ', 'ｶ', 'ｷ', 'ﾑ', 'ﾕ', 'ﾗ', 'ｾ', 'ﾈ', 'ｽ', 'ﾀ', 'ﾇ', 'ﾍ', '0', '1', '2', '3', '4', '5',
    '6', '7', '8', '9',
];

/// Печатает статусную строку зелёным с маркером "▸".
pub fn status(text: &str) {
    println!("{BRIGHT_GREEN}▸ {text}{RESET}");
}

//
// Реальная ширина терминала.
//
// $COLUMNS — переменная шелла, обычно НЕ проброшена в дочерний
// процесс (не exported), поэтому читать её из env почти всегда
// бессмысленно. Если строка окажется шире настоящего терминала,
// она перенесётся, и на следующем кадре "\x1b[H" (домой) уже не
// совпадёт с логическими координатами кадра — с каждым кадром
// рисунок расползается по диагонали. `tput cols` спрашивает
// реальный размер у самого терминала.
//
fn terminal_width() -> usize {
    std::process::Command::new("tput")
        .arg("cols")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|text| text.trim().parse::<usize>().ok())
        .filter(|&width| width > 0)
        .map(|width| width.min(200))
        .unwrap_or(60)
}

/// Краткая анимация "цифрового дождя" перед подключением.
///
/// Чистая заставка: ~1.2 секунды, синхронно, до старта реальной
/// работы клиента.
pub fn rain_intro() {
    //
    // -1 запасом: некоторые терминалы переносят строку, если она
    // заполняет колонку впритык до последнего символа.
    //
    let width = terminal_width().saturating_sub(1).max(20);

    let height: usize = 12;

    let mut rng_state: u64 = 0x9e3779b97f4a7c15;

    let mut next_char = move || -> char {
        //
        // Простой xorshift — для визуального эффекта
        // криптографическая случайность не нужна.
        //
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 7;
        rng_state ^= rng_state << 17;

        RAIN_CHARS[(rng_state as usize) % RAIN_CHARS.len()]
    };

    let mut heads: Vec<i32> = (0..width)
        .map(|column| -((column % height) as i32))
        .collect();

    print!("\x1b[2J");

    for _frame in 0..24 {
        print!("\x1b[H");

        for row in 0..height {
            let mut line = String::with_capacity(width * 4);

            for (column, head) in heads.iter().enumerate() {
                let distance = head - row as i32;

                if distance == 0 {
                    line.push_str(BOLD_GREEN);
                    line.push(next_char());
                    line.push_str(RESET);
                } else if (1..=3).contains(&distance) {
                    line.push_str(DIM_GREEN);
                    line.push(next_char());
                    line.push_str(RESET);
                } else {
                    line.push(' ');
                }

                let _ = column;
            }

            println!("{line}");
        }

        for head in heads.iter_mut() {
            *head += 1;

            if *head > height as i32 + 3 {
                *head = -((next_char() as i32) % height as i32);
            }
        }

        let _ = io::stdout().flush();

        std::thread::sleep(Duration::from_millis(70));
    }

    print!("\x1b[2J\x1b[H");

    let _ = io::stdout().flush();
}

/// ASCII-заставка с названием клиента.
pub fn banner() {
    println!(
        "{BOLD_GREEN}\
 ______  ______ __ __ ______ __  __ ______ __   __ ______
/\\  == \\/\\  __ /\\ \\_\\ /\\  == /\\ \\_\\ /\\  __ /\\ \"-./  /\\  ___\\
\\ \\  _-/\\ \\  __\\\\ \\____ \\ \\  _-\\ \\  __ \\ \\ \\/ \\ \\ \\-./\\ \\  __\\
 \\ \\_\\   \\ \\_____\\/\\_____ \\ \\_\\  \\ \\_\\ \\_\\ \\_____\\ \\_\\ \\ \\ \\_____\\
  \\/_/    \\/_____/\\/_____/\\/_/   \\/_/\\/_/\\/_____/\\/_/  \\/_/\\/_____/{RESET}"
    );

    println!("{DIM_GREEN}VPN client — wake up.{RESET}");

    println!();
}

/// Баннер "туннель открыт" — после успешного full-tunnel routing.
pub fn tunnel_open_banner() {
    println!();

    println!("{BOLD_GREEN}╔══════════════════════════════╗{RESET}");
    println!("{BOLD_GREEN}║        TUNNEL IS OPEN        ║{RESET}");
    println!("{BOLD_GREEN}╚══════════════════════════════╝{RESET}");

    println!();
}

/// Живой индикатор потока пакетов: печатает зелёный символ без
/// перевода строки, с throttling, чтобы не заспамить терминал
/// при интенсивном трафике.
pub struct FlowIndicator {
    last_printed: Instant,

    min_interval: Duration,
}

impl FlowIndicator {
    pub fn new() -> Self {
        Self {
            last_printed: Instant::now() - Duration::from_secs(1),

            min_interval: Duration::from_millis(60),
        }
    }

    /// `symbol`: '▸' для исходящих (TUN -> QUIC), '◂' для
    /// входящих (QUIC -> TUN).
    pub fn pulse(&mut self, symbol: char) {
        let now = Instant::now();

        if now.duration_since(self.last_printed) < self.min_interval {
            return;
        }

        self.last_printed = now;

        print!("{GREEN}{symbol}{RESET}");

        let _ = io::stdout().flush();
    }
}
