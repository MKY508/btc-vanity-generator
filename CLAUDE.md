# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
# Build release (optimized)
cargo build --release

# Run
./target/release/btc-vanity

# Build debug
cargo build
```

## Architecture

Single-file Rust CLI application (`src/main.rs`) for generating Bitcoin vanity addresses.

**Core Components:**
- Interactive TUI with menu navigation (main menu → settings/generate/about)
- Multi-threaded address generation using `std::thread`
- Progress display with ANSI escape codes for in-place updates

**Address Types:**
- Taproot (bc1p) - BIP86 path `m/86'/0'/0'/0/0`
- SegWit (bc1q) - BIP84 path `m/84'/0'/0'/0/0`
- Legacy (1...) - BIP44 path `m/44'/0'/0'/0/0`
- P2SH (3...) - BIP44 path `m/44'/0'/0'/0/0`

**Key Dependencies:**
- `bitcoin` - Address generation and key derivation
- `bip39` - Mnemonic generation from entropy
- `rand_xoshiro` - Fast PRNG (Xoshiro256PlusPlus)

**Performance Notes:**
- Release profile uses LTO, single codegen-unit, and opt-level 3
- Workers use local counters with batched atomic updates to reduce contention
- Target strings are pre-computed before search loop
