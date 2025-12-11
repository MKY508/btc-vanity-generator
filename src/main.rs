use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, ExtendedPrivKey};
use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
use bitcoin::{Address, Network, PrivateKey, PublicKey};
use rand::RngCore;
use rand_xoshiro::Xoshiro256PlusPlus;
use rand_xoshiro::rand_core::SeedableRng;
use std::fmt::Write as FmtWrite;
use std::io::{self, Write};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

const VERSION: &str = "0.1.0";
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

#[derive(Clone)]
struct Target { raw: String, full: String }

#[derive(Clone)]
struct Settings {
    addr_type: Addr,
    match_mode: Match,
    output: Out,
    threads: usize,
    batch_size: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            addr_type: Addr::Taproot,
            match_mode: Match::Prefix,
            output: Out::Mnemonic,
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
    print!("\x1B[2J\x1B[H");
    io::stdout().flush().unwrap();
}

fn input(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut s = String::new();
    io::stdin().read_line(&mut s).unwrap();
    s.trim().into()
}

fn pause() {
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
    let low = s.to_lowercase();
    let bad: Vec<_> = low.chars().filter(|c| !cs.contains(*c)).collect();
    if bad.is_empty() { Some(low) } else { None }
}

fn main() {
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

        match input("\n  请选择: ").as_str() {
            "1" => generate(&settings),
            "2" => settings_menu(&mut settings),
            "3" => about(),
            "0" | "q" => { clear(); println!("\n  再见!\n"); break; }
            _ => {}
        }
    }
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
        println!("    [4] 线程数量    {}", settings.threads);
        println!("    [5] 批处理量    {}", settings.batch_size);
        println!();
        println!("    [0] 返回");

        match input("\n  请选择: ").as_str() {
            "1" => {
                clear();
                println!("\n  选择地址类型:\n");
                println!("    [1] Taproot (bc1p) - BIP86");
                println!("    [2] SegWit  (bc1q) - BIP84");
                println!("    [3] Legacy  (1...) - BIP44");
                println!("    [4] P2SH    (3...) - BIP44");
                settings.addr_type = match input("\n  选择 [1]: ").as_str() {
                    "2" => Addr::SegWit, "3" => Addr::Legacy, "4" => Addr::P2SH, _ => Addr::Taproot
                };
            }
            "2" => {
                clear();
                println!("\n  选择匹配模式:\n");
                println!("    [1] 前缀匹配 ({}xxx...)", pfx(settings.addr_type));
                println!("    [2] 后缀匹配 (...xxx)");
                println!("    [3] 包含匹配 (...xxx...)");
                settings.match_mode = match input("\n  选择 [1]: ").as_str() {
                    "2" => Match::Suffix, "3" => Match::Contains, _ => Match::Prefix
                };
            }
            "3" => {
                clear();
                println!("\n  选择输出格式:\n");
                println!("    [1] 助记词 (24词)");
                println!("    [2] 私钥 (WIF格式)");
                println!("    [3] 两者都输出");
                settings.output = match input("\n  选择 [1]: ").as_str() {
                    "2" => Out::Wif, "3" => Out::Both, _ => Out::Mnemonic
                };
            }
            "4" => {
                clear();
                let max = num_cpus::get();
                println!("\n  设置线程数量 (1-{}):", max);
                println!("  当前: {}", settings.threads);
                if let Ok(n) = input("\n  输入: ").parse::<usize>() {
                    if n >= 1 && n <= max { settings.threads = n; }
                }
            }
            "5" => {
                clear();
                println!("\n  设置批处理量 (64-2048):");
                println!("  当前: {}", settings.batch_size);
                println!("  提示: 较大的值减少同步开销");
                if let Ok(n) = input("\n  输入: ").parse::<u64>() {
                    if n >= 64 && n <= 2048 { settings.batch_size = n; }
                }
            }
            "0" | "" => break,
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
    pause();
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
    println!();
    println!("    输入目标字符 (多个用逗号分隔)");
    println!("    例如: test,6666,abc");
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
    println!("    线程数量: {}", settings.threads);

    if input("\n  开始搜索? [Y/n]: ").to_lowercase() == "n" { return; }

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
            io::stdout().flush().unwrap();
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
            let mut rng = Xoshiro256PlusPlus::from_entropy();
            let mut ent = [0u8; 32];
            let mut buf = String::with_capacity(64);
            let mut local = 0u64;

            loop {
                if stop.load(Ordering::Relaxed) { break; }

                for _ in 0..settings.batch_size {
                    rng.fill_bytes(&mut ent);

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
                            Address::p2wpkh(&pk, Network::Bitcoin).unwrap()
                        }
                        Addr::Legacy => {
                            let pk = PublicKey::new(child.to_keypair(&secp).public_key());
                            Address::p2pkh(&pk, Network::Bitcoin)
                        }
                        Addr::P2SH => {
                            let pk = PublicKey::new(child.to_keypair(&secp).public_key());
                            Address::p2shwpkh(&pk, Network::Bitcoin).unwrap()
                        }
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
                                    Some(PrivateKey::new(child.private_key, Network::Bitcoin).to_wif())
                                } else { None };
                                let _ = tx.send(Found {
                                    addr: buf.clone(),
                                    mnemonic: if settings.output == Out::Mnemonic || settings.output == Out::Both {
                                        Some(mn.to_string())
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

        println!("    派生路径: {}", deriv(settings.addr_type));
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
