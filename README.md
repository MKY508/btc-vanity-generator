# BTC Vanity Generator

比特币靓号地址生成器，支持所有主流地址类型。

## 功能

- 支持 bc1p (Taproot) / bc1q (SegWit) / 1xxx (Legacy) / 3xxx (P2SH)
- 多目标同时搜索
- 实时进度条 + 运气值显示
- 输出助记词或私钥

## 速度估算

基于 Apple M3 芯片 (~15000/s)：

**Bech32 地址 (bc1p/bc1q)** - 32字符集

| 位数 | 期望尝试 | 预计时间 |
|------|----------|----------|
| 3 | 32,768 | 2秒 |
| 4 | 1,048,576 | 1分钟 |
| 5 | 33,554,432 | 37分钟 |
| 6 | 1,073,741,824 | 20小时 |
| 7 | 34,359,738,368 | 26天 |

**Base58 地址 (1xxx/3xxx)** - 58字符集

| 位数 | 期望尝试 | 预计时间 |
|------|----------|----------|
| 3 | 195,112 | 13秒 |
| 4 | 11,316,496 | 12分钟 |
| 5 | 656,356,768 | 12小时 |
| 6 | 38,068,692,544 | 29天 |

> 实际时间取决于运气，可能更快或更慢

## 编译

### 依赖

- Rust 1.70+

### macOS

```bash
# 安装 Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 编译
cd btc-vanity-generator
cargo build --release

# 运行
./target/release/btc-vanity
```

### Linux (Ubuntu/Debian)

```bash
# 安装依赖
sudo apt update
sudo apt install -y build-essential curl

# 安装 Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# 编译
cd btc-vanity-generator
cargo build --release

# 运行
./target/release/btc-vanity
```

### Windows

```powershell
# 1. 下载并安装 Rust: https://rustup.rs
# 2. 安装 Visual Studio Build Tools (C++ 工具链)

# 编译
cd btc-vanity-generator
cargo build --release

# 运行
.\target\release\btc-vanity.exe
```

## 使用

```
=== BTC Vanity Generator ===

地址类型:
  1. bc1p (Taproot)
  2. bc1q (SegWit)
  3. 1xxx (Legacy)
  4. 3xxx (P2SH)

选择 [1]: 1

目标 (bc1p后面的字符, 逗号分隔):
  字符集: qpzry9x8gf2tvdw0s3jn54khce6mua7l

输入: test,6666

搜索中...

[  3.2%] 1m23s | 14523/s | 运气:好运 | ETA:42m

=== 找到! ===

地址: bc1ptest7x8gf2tvdw0s3jn54khce6mua7lqpzry9
助记词: abandon ability able ...
路径: m/86'/0'/0'/0/0

耗时: 2m15s | 尝试: 1,234,567 | 运气: 0.85x
```

## 字符集

**Bech32** (bc1p/bc1q): `qpzry9x8gf2tvdw0s3jn54khce6mua7l`
- 不含: 1, b, i, o

**Base58** (1xxx/3xxx): `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`
- 不含: 0, O, I, l

## 派生路径

| 类型 | 路径 | BIP |
|------|------|-----|
| Taproot | m/86'/0'/0'/0/0 | BIP86 |
| SegWit | m/84'/0'/0'/0/0 | BIP84 |
| Legacy | m/44'/0'/0'/0/0 | BIP44 |
| P2SH | m/44'/0'/0'/0/0 | BIP44 |

## 安全提示

- 生成的密钥请离线保存
- 不要截图或存在联网设备
- 本工具完全本地运行，不联网

## License

MIT
