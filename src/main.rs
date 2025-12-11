use anyhow::Result;
use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, ExtendedPrivKey};
use bitcoin::secp256k1::{Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::{Address, Network, PrivateKey, PublicKey};
use crossterm::event::{self, Event, KeyCode, KeyEvent};
use crossterm::terminal::{self, ClearType};
use rand::rngs::OsRng;
use rand::RngCore;
use rand_xoshiro::rand_core::SeedableRng;
use rand_xoshiro::Xoshiro256PlusPlus;
use rustyline::DefaultEditor;
use std::fmt::Write as FmtWrite;
use std::io::{self, Write};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

const VERSION: &str = "0.2.0";
const AUTHOR_EMAIL: &str = "mky369258@gmail.com";
const AUTHOR_GITHUB: &str = "MKY508";

const BECH32: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BASE58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

#[derive(Clone, Copy, PartialEq)]
enum Addr { Taproot, SegWit, Legacy, P2SH }

#[derive(Clone, Copy, PartialEq)]
enum Match { Prefix, Suffix, Contains }

#[derive(Clone, Copy, PartialEq)]
enum Out { Mnemonic, Wif, Both }

#[derive(Clone, Copy, PartialEq)]
enum RngMode { Secure, Fast }

#[derive(Clone)]
struct Target { raw: String, full: String }

#[derive(Clone)]
struct Settings {
    addr_type: Addr,
    match_mode: Match,
    output: Out,
    rng_mode: RngMode,
    threads: usize,
    batch_size: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            addr_type: Addr::Taproot,
            match_mode: Match::Prefix,
            output: Out::Mnemonic,
            rng_mode: RngMode::Secure,
            threads: num_cpus::get(),
            batch_size: 512,
        }
    }
}

struct Found {
    addr: String,
    mnemonic: Option<String>,
    wif: Option<String>,
    target: String,
}

fn clear() {
    print!("{}", crossterm::terminal::Clear(ClearType::All));
    print!("{}", crossterm::cursor::MoveTo(0, 0));
    io::stdout().flush().ok();
}

fn read_key() -> Option<char> {
    terminal::enable_raw_mode().ok()?;
    let result = loop {
        if event::poll(Duration::from_millis(100)).unwrap_or(false) {
            if let Ok(Event::Key(KeyEvent { code, .. })) = event::read() {
                break match code {
                    KeyCode::Char(c) => Some(c),
                    KeyCode::Enter => Some('\n'),
                    KeyCode::Esc => Some('\x1b'),
                    _ => None,
                };
            }
        }
    };
    terminal::disable_raw_mode().ok();
    result
}

fn input(prompt: &str) -> String {
    terminal::disable_raw_mode().ok();
    let mut rl = match DefaultEditor::new() {
        Ok(r) => r,
        Err(_) => {
            // fallback to basic input
            print!("{}", prompt);
            io::stdout().flush().ok();
            let mut s = String::new();
            io::stdin().read_line(&mut s).ok();
            return s.trim().into();
        }
    };
    match rl.readline(prompt) {
        Ok(line) => line.trim().to_string(),
        Err(_) => String::new(),
    }
}

fn pause() {
    terminal::disable_raw_mode().ok();
    input("\n按 Enter 继续...");
}

fn progress_bar(pct: f64, width: usize) -> String {
    let filled = ((pct / 100.0) * width as f64).min(width as f64) as usize;
    let empty = width.saturating_sub(filled);
    format!("[{}{}]", "=".repeat(filled), " ".repeat(empty))
}

fn charset(a: Addr) -> &'static str {
    match a { Addr::Taproot | Addr::SegWit => BECH32, _ => BASE58 }
}

fn is_bech32(a: Addr) -> bool {
    matches!(a, Addr::Taproot | Addr::SegWit)
}

fn base(a: Addr) -> u64 {
    match a { Addr::Taproot | Addr::SegWit => 32, _ => 58 }
}

fn pfx(a: Addr) -> &'static str {
    match a { Addr::Taproot => "bc1p", Addr::SegWit => "bc1q", Addr::Legacy => "1", Addr::P2SH => "3" }
}

fn deriv(a: Addr) -> &'static str {
    match a { Addr::Taproot => "m/86'/0'/0'/0/0", Addr::SegWit => "m/84'/0'/0'/0/0", _ => "m/44'/0'/0'/0/0" }
}

fn addr_name(a: Addr) -> &'static str {
    match a { Addr::Taproot => "Taproot (bc1p)", Addr::SegWit => "SegWit (bc1q)", Addr::Legacy => "Legacy (1...)", Addr::P2SH => "P2SH (3...)" }
}

fn match_name(m: Match) -> &'static str {
    match m { Match::Prefix => "前缀匹配", Match::Suffix => "后缀匹配", Match::Contains => "包含匹配" }
}

fn out_name(o: Out) -> &'static str {
    match o { Out::Mnemonic => "助记词", Out::Wif => "私钥 (WIF)", Out::Both => "助记词 + 私钥" }
}

fn rng_name(r: RngMode) -> &'static str {
    match r { RngMode::Secure => "安全 (OsRng)", RngMode::Fast => "快速 (Xoshiro)" }
}

fn exp(len: usize, a: Addr) -> u64 { base(a).pow(len as u32) }

fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 { result.insert(0, ','); }
        result.insert(0, c);
    }
    result
}

fn fmt_time(s: u64) -> String {
    match s {
        0..=59 => format!("{}s", s),
        60..=3599 => format!("{}m{}s", s/60, s%60),
        3600..=86399 => format!("{}h{}m", s/3600, (s%3600)/60),
        _ => format!("{}d{}h", s/86400, (s%86400)/3600),
    }
}

fn validate(s: &str, a: Addr) -> Option<String> {
    let cs = charset(a);
    if is_bech32(a) {
        // Bech32: 只允许小写
        let low = s.to_lowercase();
        if low.chars().all(|c| cs.contains(c)) { Some(low) } else { None }
    } else {
        // Base58: 保留大小写
        if s.chars().all(|c| cs.contains(c)) { Some(s.to_string()) } else { None }
    }
}

fn main() -> Result<()> {
    let mut settings = Settings::default();

    loop {
        clear();
        println!();
        println!("  ╭─────────────────────────────────────────╮");
        println!("  │                                         │");
        println!("  │      BTC Vanity Generator v{}        │", VERSION);
        println!("  │      ─────────────────────────          │");
        println!("  │                                         │");
        println!("  │      [1] 开始生成                       │");
        println!("  │      [2] 设置                           │");
        println!("  │      [3] 关于                           │");
        println!("  │      [0] 退出                           │");
        println!("  │                                         │");
        println!("  ╰─────────────────────────────────────────╯");
        println!();
        println!("  按 1-3 选择  |  0/Esc 退出");

        match read_key() {
            Some('1') => generate(&settings),
            Some('2') => settings_menu(&mut settings),
            Some('3') => about(),
            Some('0') | Some('q') | Some('\x1b') => { clear(); println!("\n  再见!\n"); break; }
            _ => {}
        }
    }
    Ok(())
}

fn settings_menu(settings: &mut Settings) {
    loop {
        clear();
        println!();
        println!("  ╭─────────────────────────────────────────╮");
        println!("  │               设    置                  │");
        println!("  ╰─────────────────────────────────────────╯");
        println!();
        println!("    [1] 地址类型    {}", addr_name(settings.addr_type));
        println!("    [2] 匹配模式    {}", match_name(settings.match_mode));
        println!("    [3] 输出格式    {}", out_name(settings.output));
        println!("    [4] 随机源      {}", rng_name(settings.rng_mode));
        println!("    [5] 线程数量    {}", settings.threads);
        println!("    [6] 批处理量    {}", settings.batch_size);
        println!();
        println!("  按 1-6 选择  |  Esc 返回");

        match read_key() {
            Some('1') => {
                clear();
                println!("\n  选择地址类型:\n");
                println!("    [1] Taproot (bc1p) - BIP86");
                println!("    [2] SegWit  (bc1q) - BIP84");
                println!("    [3] Legacy  (1...) - BIP44");
                println!("    [4] P2SH    (3...) - BIP44");
                println!();
                println!("  按 1-4 选择  |  Esc 返回");
                match read_key() {
                    Some('1') => settings.addr_type = Addr::Taproot,
                    Some('2') => settings.addr_type = Addr::SegWit,
                    Some('3') => settings.addr_type = Addr::Legacy,
                    Some('4') => settings.addr_type = Addr::P2SH,
                    _ => {}
                }
            }
            Some('2') => {
                clear();
                println!("\n  选择匹配模式:\n");
                println!("    [1] 前缀匹配 ({}xxx...)", pfx(settings.addr_type));
                println!("    [2] 后缀匹配 (...xxx)");
                println!("    [3] 包含匹配 (...xxx...)");
                println!();
                println!("  按 1-3 选择  |  Esc 返回");
                match read_key() {
                    Some('1') => settings.match_mode = Match::Prefix,
                    Some('2') => settings.match_mode = Match::Suffix,
                    Some('3') => settings.match_mode = Match::Contains,
                    _ => {}
                }
            }
            Some('3') => {
                clear();
                println!("\n  选择输出格式:\n");
                println!("    [1] 助记词 (24词)");
                println!("    [2] 私钥 (WIF格式) - 更快!");
                println!("    [3] 两者都输出");
                println!();
                println!("  按 1-3 选择  |  Esc 返回");
                match read_key() {
                    Some('1') => settings.output = Out::Mnemonic,
                    Some('2') => settings.output = Out::Wif,
                    Some('3') => settings.output = Out::Both,
                    _ => {}
                }
            }
            Some('4') => {
                clear();
                println!("\n  选择随机源:\n");
                println!("    [1] 安全 (OsRng) - 密码学安全，推荐");
                println!("    [2] 快速 (Xoshiro) - 更快但非密码学安全");
                println!();
                println!("    ⚠ 警告: 快速模式使用伪随机数生成器");
                println!("    理论上可被预测，仅建议测试使用");
                println!();
                println!("  按 1-2 选择  |  Esc 返回");
                match read_key() {
                    Some('1') => settings.rng_mode = RngMode::Secure,
                    Some('2') => settings.rng_mode = RngMode::Fast,
                    _ => {}
                }
            }
            Some('5') => {
                clear();
                let max = num_cpus::get();
                println!("\n  设置线程数量 (1-{}):", max);
                println!("  当前: {}", settings.threads);
                println!();
                println!("  输入数字后按 Enter  |  直接按 Esc 返回");
                let s = input("\n  输入: ");
                if let Ok(n) = s.parse::<usize>() {
                    if n >= 1 && n <= max { settings.threads = n; }
                }
            }
            Some('6') => {
                clear();
                println!("\n  设置批处理量 (64-2048):");
                println!("  当前: {}", settings.batch_size);
                println!("  提示: 较大的值减少同步开销");
                println!();
                println!("  输入数字后按 Enter  |  直接按 Esc 返回");
                let s = input("\n  输入: ");
                if let Ok(n) = s.parse::<u64>() {
                    if n >= 64 && n <= 2048 { settings.batch_size = n; }
                }
            }
            Some('\x1b') => break,
            _ => {}
        }
    }
}

fn about() {
    clear();
    println!();
    println!("  ╭─────────────────────────────────────────╮");
    println!("  │               关    于                  │");
    println!("  ╰─────────────────────────────────────────╯");
    println!();
    println!("    BTC Vanity Generator");
    println!("    Version {}", VERSION);
    println!();
    println!("    比特币靓号地址生成器");
    println!("    支持 Taproot / SegWit / Legacy / P2SH");
    println!();
    println!("  ─────────────────────────────────────────");
    println!();
    println!("    Author:  {}", AUTHOR_GITHUB);
    println!("    Email:   {}", AUTHOR_EMAIL);
    println!("    GitHub:  github.com/{}", AUTHOR_GITHUB);
    println!();
    println!("  ─────────────────────────────────────────");
    println!();
    println!("    本工具完全本地运行，不联网");
    println!("    请妥善保管生成的密钥");
    println!();
    println!("  按任意键返回");
    read_key();
}

fn generate(settings: &Settings) {
    clear();
    println!();
    println!("  ╭─────────────────────────────────────────╮");
    println!("  │             输入目标                    │");
    println!("  ╰─────────────────────────────────────────╯");
    println!();
    println!("    地址前缀: {}", pfx(settings.addr_type));
    println!("    字符集:   {}", charset(settings.addr_type));
    if !is_bech32(settings.addr_type) {
        println!("    注意:     Base58 区分大小写!");
    }
    println!();
    println!("    输入目标字符 (多个用逗号分隔)");
    println!("    例如: test,6666,abc");
    println!();
    println!("  ←→ 移动光标  |  Enter 确认  |  留空按 Enter 返回");
    println!();

    let raw = input("  目标: ");
    if raw.is_empty() { return; }

    let targets: Vec<Target> = raw.split(',')
        .filter_map(|s| {
            let s = s.trim();
            if let Some(v) = validate(s, settings.addr_type) {
                let full = match settings.match_mode {
                    Match::Prefix => format!("{}{}", pfx(settings.addr_type), v),
                    _ => v.clone(),
                };
                Some(Target { raw: v, full })
            } else {
                println!("    跳过 '{}': 包含无效字符", s);
                None
            }
        })
        .collect();

    if targets.is_empty() {
        println!("\n  无有效目标!");
        pause();
        return;
    }

    clear();
    println!();
    println!("  ╭─────────────────────────────────────────╮");
    println!("  │             确认配置                    │");
    println!("  ╰─────────────────────────────────────────╯");
    println!();
    println!("    目标:");
    for t in &targets {
        let show = match settings.match_mode {
            Match::Prefix => format!("{}...", t.full),
            Match::Suffix => format!("...{}", t.raw),
            Match::Contains => format!("...{}...", t.raw),
        };
        let e = exp(t.raw.len(), settings.addr_type);
        println!("      {} ({}位, 期望{}次)", show, t.raw.len(), fmt_num(e));
    }
    println!();
    println!("    地址类型: {}", addr_name(settings.addr_type));
    println!("    匹配模式: {}", match_name(settings.match_mode));
    println!("    输出格式: {}", out_name(settings.output));
    println!("    随机源:   {}", rng_name(settings.rng_mode));

    if settings.output == Out::Wif {
        println!();
        println!("    ⚡ 纯私钥模式: 跳过助记词生成，速度更快!");
    }

    println!();
    println!("  Enter/Y 开始  |  Esc/N 返回");

    match read_key() {
        Some('n') | Some('N') | Some('\x1b') => return,
        _ => {}
    }

    run_search(settings.clone(), targets);
}

fn run_search(settings: Settings, targets: Vec<Target>) {
    let stop = Arc::new(AtomicBool::new(false));
    let cnt = Arc::new(AtomicU64::new(0));
    let t0 = Instant::now();
    let (tx, rx) = mpsc::channel::<Found>();

    let min_exp: u64 = targets.iter().map(|t| exp(t.raw.len(), settings.addr_type)).min().unwrap_or(1);

    clear();
    println!();
    println!("  ╭─────────────────────────────────────────╮");
    println!("  │             搜索中...                   │");
    println!("  ╰─────────────────────────────────────────╯");
    println!();
    println!();
    println!();
    println!();
    println!();

    let p_stop = stop.clone();
    let p_cnt = cnt.clone();
    let prog = thread::spawn(move || {
        let mut last = 0u64;
        let bar_width = 35;

        loop {
            thread::sleep(Duration::from_millis(200));
            if p_stop.load(Ordering::Relaxed) { break; }

            let cur = p_cnt.load(Ordering::Relaxed);
            let spd = (cur - last) * 5;
            last = cur;

            let elapsed = t0.elapsed().as_secs();
            let pct = (cur as f64 / min_exp as f64 * 100.0).min(100.0);
            let luck = if cur > 0 { min_exp as f64 / cur as f64 } else { 0.0 };

            let luck_tag = if luck > 2.0 { "欧皇" } else if luck > 1.0 { "好运" } else if luck > 0.5 { "正常" } else { "非酋" };

            let eta = if spd > 0 && cur < min_exp {
                fmt_time((min_exp - cur) / spd)
            } else if cur >= min_exp { "随时".into() } else { "...".into() };

            print!("\x1B[6;1H");
            println!("    {} {:>5.1}%", progress_bar(pct, bar_width), pct);
            println!();
            println!("    速度: {:>12}/s    已尝试: {:>15}", fmt_num(spd), fmt_num(cur));
            println!("    运气: {:>12}      ETA: {:>15}", luck_tag, eta);
            println!("    耗时: {:>12}", fmt_time(elapsed));
            io::stdout().flush().ok();
        }
    });

    let mut hs = vec![];
    let targets = Arc::new(targets);

    for _ in 0..settings.threads {
        let settings = settings.clone();
        let targets = targets.clone();
        let stop = stop.clone();
        let cnt = cnt.clone();
        let tx = tx.clone();

        hs.push(thread::spawn(move || {
            let secp = Secp256k1::new();
            let path = DerivationPath::from_str(deriv(settings.addr_type)).unwrap();
            let mut buf = String::with_capacity(64);
            let mut local = 0u64;

            // 根据设置选择 RNG
            let mut secure_rng = OsRng;
            let mut fast_rng = Xoshiro256PlusPlus::from_entropy();

            // WIF-only 模式: 直接生成随机私钥，跳过 BIP39/BIP32
            let wif_only = settings.output == Out::Wif;

            loop {
                if stop.load(Ordering::Relaxed) { break; }

                for _ in 0..settings.batch_size {
                    let (addr, mnemonic_str, secret_key) = if wif_only {
                        // 快速模式: 直接生成随机私钥
                        let mut key_bytes = [0u8; 32];
                        match settings.rng_mode {
                            RngMode::Secure => secure_rng.fill_bytes(&mut key_bytes),
                            RngMode::Fast => fast_rng.fill_bytes(&mut key_bytes),
                        }

                        let sk = match SecretKey::from_slice(&key_bytes) {
                            Ok(k) => k,
                            Err(_) => continue,
                        };

                        let addr = match settings.addr_type {
                            Addr::Taproot => {
                                let kp = sk.keypair(&secp);
                                let (x, _) = XOnlyPublicKey::from_keypair(&kp);
                                Address::p2tr(&secp, x, None, Network::Bitcoin)
                            }
                            Addr::SegWit => {
                                let pk = PublicKey::new(sk.public_key(&secp));
                                match Address::p2wpkh(&pk, Network::Bitcoin) {
                                    Ok(a) => a,
                                    Err(_) => continue,
                                }
                            }
                            Addr::Legacy => {
                                let pk = PublicKey::new(sk.public_key(&secp));
                                Address::p2pkh(&pk, Network::Bitcoin)
                            }
                            Addr::P2SH => {
                                let pk = PublicKey::new(sk.public_key(&secp));
                                match Address::p2shwpkh(&pk, Network::Bitcoin) {
                                    Ok(a) => a,
                                    Err(_) => continue,
                                }
                            }
                        };
                        (addr, None, sk)
                    } else {
                        // 标准模式: BIP39 助记词 -> BIP32 派生
                        let mut ent = [0u8; 32];
                        match settings.rng_mode {
                            RngMode::Secure => secure_rng.fill_bytes(&mut ent),
                            RngMode::Fast => fast_rng.fill_bytes(&mut ent),
                        }

                        let mn = match Mnemonic::from_entropy(&ent) { Ok(m) => m, Err(_) => continue };
                        let seed = mn.to_seed("");
                        let root = match ExtendedPrivKey::new_master(Network::Bitcoin, &seed) { Ok(r) => r, Err(_) => continue };
                        let child = match root.derive_priv(&secp, &path) { Ok(k) => k, Err(_) => continue };

                        let addr = match settings.addr_type {
                            Addr::Taproot => {
                                let kp = child.to_keypair(&secp);
                                let (x, _) = XOnlyPublicKey::from_keypair(&kp);
                                Address::p2tr(&secp, x, None, Network::Bitcoin)
                            }
                            Addr::SegWit => {
                                let pk = PublicKey::new(child.to_keypair(&secp).public_key());
                                match Address::p2wpkh(&pk, Network::Bitcoin) {
                                    Ok(a) => a,
                                    Err(_) => continue,
                                }
                            }
                            Addr::Legacy => {
                                let pk = PublicKey::new(child.to_keypair(&secp).public_key());
                                Address::p2pkh(&pk, Network::Bitcoin)
                            }
                            Addr::P2SH => {
                                let pk = PublicKey::new(child.to_keypair(&secp).public_key());
                                match Address::p2shwpkh(&pk, Network::Bitcoin) {
                                    Ok(a) => a,
                                    Err(_) => continue,
                                }
                            }
                        };
                        (addr, Some(mn.to_string()), child.private_key)
                    };

                    buf.clear();
                    write!(&mut buf, "{}", addr).unwrap();
                    local += 1;

                    for t in targets.iter() {
                        let hit = match settings.match_mode {
                            Match::Prefix => buf.starts_with(&t.full),
                            Match::Suffix => buf.ends_with(&t.full),
                            Match::Contains => buf.contains(&t.full),
                        };
                        if hit {
                            cnt.fetch_add(local, Ordering::Relaxed);
                            if !stop.swap(true, Ordering::Relaxed) {
                                let wif = if settings.output == Out::Wif || settings.output == Out::Both {
                                    Some(PrivateKey::new(secret_key, Network::Bitcoin).to_wif())
                                } else { None };
                                let _ = tx.send(Found {
                                    addr: buf.clone(),
                                    mnemonic: if settings.output == Out::Mnemonic || settings.output == Out::Both {
                                        mnemonic_str.clone()
                                    } else { None },
                                    wif,
                                    target: t.raw.clone(),
                                });
                            }
                            return;
                        }
                    }
                }

                if local >= 1000 {
                    cnt.fetch_add(local, Ordering::Relaxed);
                    local = 0;
                }
            }
            cnt.fetch_add(local, Ordering::Relaxed);
        }));
    }

    drop(tx);

    if let Ok(r) = rx.recv() {
        let dur = t0.elapsed();
        let tot = cnt.load(Ordering::Relaxed);
        let e = exp(r.target.len(), settings.addr_type);
        let luck = e as f64 / tot as f64;

        clear();
        println!();
        println!("  ╭─────────────────────────────────────────╮");
        println!("  │            * 找到了! *                  │");
        println!("  ╰─────────────────────────────────────────╯");
        println!();
        println!("    地址:");
        println!("    {}", r.addr);
        println!();

        if let Some(ref m) = r.mnemonic {
            println!("    助记词:");
            println!("    {}", m);
            println!();
        }

        if let Some(ref w) = r.wif {
            println!("    私钥 (WIF):");
            println!("    {}", w);
            println!();
        }

        if r.mnemonic.is_some() {
            println!("    派生路径: {}", deriv(settings.addr_type));
        }
        println!("    匹配目标: {}", r.target);
        println!();
        println!("  ─────────────────────────────────────────");
        println!("    耗时: {:.2?}", dur);
        println!("    尝试: {} 次", fmt_num(tot));
        println!("    运气: {:.2}x (期望 {} 次)", luck, fmt_num(e));
        println!("  ─────────────────────────────────────────");
        println!();
        println!("    !! 请立即安全保存以上密钥 !!");

        pause();
    }

    for h in hs { let _ = h.join(); }
    let _ = prog.join();
}
