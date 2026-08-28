//
// Чисто косметика: зелёный digital rain как в Matrix.
// Превью при старте и тот же дождь, пока туннель гоняет пакеты.
// На протокол не влияет.
//

use std::{
    io::{self, Write},
    time::{Duration, Instant},
};

const RESET: &str = "\x1b[0m";
const BRIGHT_GREEN: &str = "\x1b[92m";
const BOLD_GREEN: &str = "\x1b[1;32m";
const DIM_GREEN: &str = "\x1b[2;32m";
const HEAD: &str = "\x1b[1;97m";
const GREEN: &str = "\x1b[32m";

const HIDE_CURSOR: &str = "\x1b[?25l";
const SHOW_CURSOR: &str = "\x1b[?25h";

//
// Полуширинная катакана + латиница/цифры: 1 колонка в нормальном
// моноширинном шрифте. Полноширинные ハ/ミ в Terminal.app занимают
// две клетки и ломают перерисовку.
//
const GLYPHS: &[char] = &[
    'ｱ', 'ｲ', 'ｳ', 'ｴ', 'ｵ', 'ｶ', 'ｷ', 'ｸ', 'ｹ', 'ｺ', 'ｻ', 'ｼ', 'ｽ', 'ｾ', 'ｿ', 'ﾀ', 'ﾁ', 'ﾂ', 'ﾃ',
    'ﾄ', 'ﾅ', 'ﾆ', 'ﾇ', 'ﾈ', 'ﾉ', 'ﾊ', 'ﾋ', 'ﾌ', 'ﾍ', 'ﾎ', 'ﾏ', 'ﾐ', 'ﾑ', 'ﾒ', 'ﾓ', 'ﾔ', 'ﾕ', 'ﾖ',
    'ﾗ', 'ﾘ', 'ﾙ', 'ﾚ', 'ﾛ', 'ﾜ', 'ﾝ', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'Z',
    ':', '.', '"', '=', '*', '+', '<', '>',
];

/// Печатает статусную строку зелёным с маркером "▸".
pub fn status(text: &str) {
    println!("{BRIGHT_GREEN}▸ {text}{RESET}");
}

fn terminal_size() -> (usize, usize) {
    let width = tput("cols").unwrap_or(60).clamp(20, 200);

    let height = tput("lines").unwrap_or(24).clamp(12, 80);

    (width, height)
}

fn tput(arg: &str) -> Option<usize> {
    std::process::Command::new("tput")
        .arg(arg)
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|text| text.trim().parse::<usize>().ok())
        .filter(|&value| value > 0)
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn glyph(&mut self) -> char {
        GLYPHS[(self.next() as usize) % GLYPHS.len()]
    }

    fn below(&mut self, max: u32) -> u32 {
        if max == 0 {
            return 0;
        }

        (self.next() % u64::from(max)) as u32
    }
}

#[derive(Clone, Copy)]
struct Cell {
    ch: char,
    glow: u8,
}

impl Cell {
    fn empty() -> Self {
        Self { ch: ' ', glow: 0 }
    }
}

struct Stream {
    head: i32,
    wait: u8,
    delay: u8,
    trail: u8,
    sleep: u8,
}

struct Rain {
    width: usize,
    height: usize,
    cells: Vec<Cell>,
    streams: Vec<Stream>,
    rng: Rng,
}

impl Rain {
    fn new(width: usize, height: usize, seed: u64, dense: bool) -> Self {
        let mut rng = Rng(seed);

        let streams = (0..width)
            .map(|column| {
                let stagger = if dense {
                    rng.below((height as u32) + 4)
                } else {
                    rng.below((height as u32) * 2 + 8)
                };

                Stream {
                    head: -(stagger as i32) - (column % 7) as i32,
                    wait: rng.below(3) as u8,
                    delay: if dense {
                        rng.below(2) as u8
                    } else {
                        rng.below(3) as u8
                    },
                    trail: 10 + rng.below(14) as u8,
                    sleep: rng.below(if dense { 6 } else { 18 }) as u8,
                }
            })
            .collect();

        Self {
            width,
            height,
            cells: vec![Cell::empty(); width * height],
            streams,
            rng,
        }
    }

    fn tick(&mut self, busy: bool) {
        for cell in &mut self.cells {
            if cell.glow > 0 {
                cell.glow -= 1;

                if cell.glow == 0 {
                    cell.ch = ' ';
                } else if self.rng.below(7) == 0 {
                    cell.ch = self.rng.glyph();
                }
            }
        }

        let width = self.width;

        for column in 0..self.streams.len() {
            if self.streams[column].sleep > 0 {
                if busy {
                    self.streams[column].sleep = self.streams[column].sleep.saturating_sub(2);
                } else {
                    self.streams[column].sleep -= 1;
                }

                continue;
            }

            let delay = if busy {
                self.streams[column].delay.min(1)
            } else {
                self.streams[column].delay
            };

            if self.streams[column].wait < delay {
                self.streams[column].wait += 1;
                continue;
            }

            self.streams[column].wait = 0;
            self.streams[column].head += 1;

            let head = self.streams[column].head;

            if head >= 0 && (head as usize) < self.height {
                let index = (head as usize) * width + column;
                self.cells[index] = Cell {
                    ch: self.rng.glyph(),
                    glow: 12,
                };
            }

            let trail = self.streams[column].trail as i32;

            if head > self.height as i32 + trail {
                self.streams[column].head = -(self.rng.below(10) as i32);
                self.streams[column].sleep = if busy {
                    self.rng.below(3) as u8
                } else {
                    3 + self.rng.below(16) as u8
                };
                self.streams[column].delay = if busy {
                    self.rng.below(2) as u8
                } else {
                    self.rng.below(3) as u8
                };
                self.streams[column].trail = 8 + self.rng.below(16) as u8;
            }
        }
    }

    fn paint_row(&self, row: usize, out: &mut String) {
        let start = row * self.width;
        let line = &self.cells[start..start + self.width];

        let mut last_style = 255u8;

        for cell in line {
            let style = match cell.glow {
                0 => 0,
                11 | 12 => 1,
                8..=10 => 2,
                4..=7 => 3,
                _ => 4,
            };

            if style != last_style {
                out.push_str(match style {
                    1 => HEAD,
                    2 => BRIGHT_GREEN,
                    3 => GREEN,
                    4 => DIM_GREEN,
                    _ => RESET,
                });
                last_style = style;
            }

            out.push(if cell.glow == 0 { ' ' } else { cell.ch });
        }

        out.push_str(RESET);
        out.push_str("\x1b[K");
    }
}

fn draw_centered(width: usize, row: usize, lines: &[&str]) {
    for (offset, line) in lines.iter().enumerate() {
        let col = width.saturating_sub(line.chars().count()).saturating_div(2) + 1;

        print!(
            "\x1b[{};{}H{BOLD_GREEN}{line}{RESET}",
            row + offset,
            col.max(1)
        );
    }
}

/// Краткая анимация digital rain перед подключением.
pub fn rain_intro() {
    let (term_w, term_h) = terminal_size();

    let width = term_w.saturating_sub(1).max(20);

    let height = term_h.saturating_sub(1).max(12);

    let mut rain = Rain::new(width, height, 0x9e3779b97f4a7c15, true);

    print!("{HIDE_CURSOR}\x1b[2J");

    let frames = 36;

    let mut frame_buf = String::with_capacity(width * height * 8);

    for frame in 0..frames {
        rain.tick(true);

        print!("\x1b[H");

        frame_buf.clear();

        for row in 0..height {
            rain.paint_row(row, &mut frame_buf);
            frame_buf.push('\n');
        }

        print!("{frame_buf}");

        let overlay_row = (height / 2).saturating_sub(1).max(1);

        if frame > 8 {
            draw_centered(
                width,
                overlay_row,
                &["PAYPHONE", "Follow the white rabbit."],
            );
        }

        let _ = io::stdout().flush();

        std::thread::sleep(Duration::from_millis(45));
    }

    print!("{SHOW_CURSOR}\x1b[2J\x1b[H");

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

    println!("{DIM_GREEN}Follow the white rabbit.{RESET}");

    println!();
}

/// Баннер "туннель открыт" — после успешного full-tunnel routing.
pub fn tunnel_open_banner() {
    println!();

    println!("{BOLD_GREEN}╔══════════════════════════════╗{RESET}");
    println!("{BOLD_GREEN}║        TUNNEL IS OPEN        ║{RESET}");
    println!("{BOLD_GREEN}╚══════════════════════════════╝{RESET}");

    println!("{DIM_GREEN}Follow the white rabbit.{RESET}");

    println!();
}

/// Живой digital rain открытого туннеля.
///
/// Занимает фиксированную область и перерисовывается на месте.
/// Пакеты сгущают и ускоряют потоки.
pub struct FlowIndicator {
    rain: Rain,

    packet_count: u64,

    energy: u16,

    live: bool,

    last_draw: Instant,

    frame_buf: String,
}

impl FlowIndicator {
    pub fn new() -> Self {
        let (term_w, term_h) = terminal_size();

        let width = term_w.saturating_sub(1).max(20);

        let height = term_h.saturating_sub(14).clamp(10, 22);

        print!("{HIDE_CURSOR}");

        print!(
            "{BRIGHT_GREEN}▸ follow the white rabbit · 0 pkts{RESET}\x1b[K\n"
        );

        for _ in 0..height {
            println!();
        }

        let _ = io::stdout().flush();

        Self {
            rain: Rain::new(width, height, 0xd1b54a32d192ed03, false),
            packet_count: 0,
            energy: 0,
            live: true,
            last_draw: Instant::now() - Duration::from_secs(1),
            frame_buf: String::with_capacity(width * height * 8),
        }
    }

    /// Исходящий (`▸`) или входящий (`◂`) пакет — сгущает дождь.
    pub fn pulse(&mut self, _symbol: char) {
        self.packet_count = self.packet_count.wrapping_add(1);

        self.energy = (self.energy + 3).min(80);
    }

    /// Кадр анимации. Вызывать по таймеру (~50ms), не из каждого пакета.
    pub fn tick(&mut self) {
        if !self.live {
            return;
        }

        let now = Instant::now();

        if now.duration_since(self.last_draw) < Duration::from_millis(40) {
            return;
        }

        self.last_draw = now;

        let busy = self.energy > 0;

        self.rain.tick(busy);

        if self.energy > 0 {
            self.energy -= 1;
        }

        self.redraw();
    }

    fn redraw(&mut self) {
        let rows = self.rain.height + 1;

        print!("\x1b[{rows}A");

        print!(
            "{BRIGHT_GREEN}▸ follow the white rabbit · {} pkts{RESET}\x1b[K\n",
            self.packet_count
        );

        self.frame_buf.clear();

        for row in 0..self.rain.height {
            self.rain.paint_row(row, &mut self.frame_buf);
            self.frame_buf.push('\n');
        }

        print!("{}", self.frame_buf);

        let _ = io::stdout().flush();
    }

    /// Курсор под дождём, дальше можно обычный println!.
    pub fn finish_line(&mut self) {
        if !self.live {
            return;
        }

        self.live = false;

        print!("{SHOW_CURSOR}");

        print!("\r\x1b[2K");

        let _ = io::stdout().flush();

        println!();
    }
}

impl Drop for FlowIndicator {
    fn drop(&mut self) {
        if self.live {
            self.finish_line();
        }
    }
}
