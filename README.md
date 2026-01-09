# Bitcoin Transaction Rust Library

A comprehensive, production-ready Bitcoin transaction library with trait-based architecture supporting all major transaction types, custom sighash flags, and advanced timelock features.

[![Rust](https://img.shields.io/badge/rust-1.85.0%2B-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## 🚀 Features

### ✅ Complete Transaction Type Support
- **Legacy Transactions**: P2PKH, P2SH multisig (2-of-2, 2-of-3, m-of-n)
- **SegWit Transactions**: P2WPKH (single/multi-input), P2WSH multisig
- **Taproot Transactions**: P2TR (key-path and script-path spending)

### 🎯 Advanced Features
- **Custom Sighash Flags**: ALL, NONE, SINGLE, and ANYONECANPAY variants per input
- **Absolute Timelocks**: nLockTime with OP_CHECKLOCKTIMEVERIFY support
- **Relative Timelocks**: nSequence with OP_CHECKSEQUENCEVERIFY support
- **Trait-Based Architecture**: Unified interface across all transaction types
- **Type Safety**: Compile-time validation and comprehensive error handling

### 📊 BIP Compliance
- ✅ BIP-16 (P2SH)
- ✅ BIP-141 (Segregated Witness)
- ✅ BIP-143 (Transaction Signature Verification for Version 0 Witness Program)
- ✅ BIP-173 (Bech32 Address Format)
- ✅ BIP-340 (Schnorr Signatures)
- ✅ BIP-341 (Taproot)
- ✅ BIP-342 (Validation of Taproot Scripts)

⚠️ **Educational & Research**: While production-quality code, please conduct your own security review before production use.

---

## 📦 Installation

### Quick Start
```bash
# Clone the repository
git clone https://github.com/cenwadike/bitcoin_tx_rust
cd bitcoin_tx_rust

# Build the project
cargo build --release

# Run tests
cargo test

# Run examples
cargo run --example all_transactions
```

### As a Library
Add to your `Cargo.toml`:
```toml
[dependencies]
bitcoin-tx-rust = { path = "../bitcoin_tx_rust" }
# or from crates.io (when published)
# bitcoin-tx-rust = "0.1.0"
```

---

## 🎓 Quick Start Guide

### Simple P2WPKH Transaction
```rust
use bitcoin_tx_rust::prelude::*;

// Create transaction
let mut tx = P2WPKHTransactionWithTraits::new();

// Add input
tx.add_input([0x42; 32], 0, vec![0x00, 0x14], 100_000_000);

// Add output
tx.add_output(99_000_000, vec![0x00, 0x14]);

// Set custom sighash flag
tx.set_sighash_flag(0, SighashFlag::All).unwrap();

// Set timelock (optional)
tx.set_locktime(LockTime::BlockHeight(700000));

// Sign and broadcast...
```

### Crowdfunding with ANYONECANPAY
```rust
use bitcoin_tx_rust::prelude::*;

let mut tx = MultiInputP2WPKHTransactionWithTraits::new();

// Fixed fundraising goal
tx.add_output(1_000_000_000, vec![0x00, 0x14]); // 10 BTC

// Multiple contributors can add inputs independently
tx.add_input([0x42; 32], 0, vec![0x00, 0x14], 500_000_000);
tx.set_sighash_flag(0, SighashFlag::AllAnyoneCanPay).unwrap();

tx.add_input([0x43; 32], 0, vec![0x00, 0x14], 500_000_000);
tx.set_sighash_flag(1, SighashFlag::AllAnyoneCanPay).unwrap();

// Each contributor signs their input independently
```

### Hash Time Locked Contract (HTLC)
```rust
use bitcoin_tx_rust::prelude::*;

let mut htlc = P2WSHMultisigTransactionWithTraits::new(redeem_script);

// Absolute locktime: refund after block 800000
htlc.set_locktime(LockTime::BlockHeight(800000));

// Relative locktime: must wait 144 blocks (~1 day)
htlc.add_input([0x42; 32], 0, 100_000_000);
htlc.set_sequence(0, Sequence::from_blocks(144)).unwrap();

htlc.add_output(99_000_000, vec![0x00, 0x20]);

// Verify timelock constraints
assert!(htlc.has_any_timelock());
assert!(htlc.can_satisfy_cltv(0, LockTime::BlockHeight(750000)));
```

---

## 📚 Core Concepts

### Trait System

All transaction types implement a unified set of traits:

```rust
// Works with ANY transaction type
fn analyze_transaction<T: TimelockSupport + SighashFlagSupport>(tx: &T) {
    println!("Sighash flags: {:?}", tx.get_all_sighash_flags());
    println!("Has timelocks: {}", tx.has_any_timelock());
}

// Use with different types
analyze_transaction(&legacy_tx);
analyze_transaction(&segwit_tx);
analyze_transaction(&taproot_tx);
```

### Sighash Flags

| Flag | Value | Description | Use Case |
|------|-------|-------------|----------|
| `All` | 0x01 | Signs all inputs and outputs | Standard transactions |
| `None` | 0x02 | Signs all inputs, no outputs | Blank check |
| `Single` | 0x03 | Signs all inputs, one output | Payment channels |
| `AllAnyoneCanPay` | 0x81 | Signs one input, all outputs | Crowdfunding |
| `NoneAnyoneCanPay` | 0x82 | Signs one input, no outputs | Donation |
| `SingleAnyoneCanPay` | 0x83 | Signs one input, one output | Contribution |
| `Default` | 0x00 | Taproot only (same as ALL) | Taproot transactions |

### Timelocks

**Absolute (nLockTime)**:
```rust
// Block height
let locktime = LockTime::BlockHeight(700000);

// Unix timestamp
let locktime = LockTime::Timestamp(1700000000);
```

**Relative (nSequence)**:
```rust
// Block-based (wait N blocks)
let sequence = Sequence::from_blocks(144); // ~1 day

// Time-based (wait N * 512 seconds)
let sequence = Sequence::from_time_intervals(10); // ~5120 seconds
```

---

## 🔥 Running Examples

### Example 1: All Transaction Types
```bash
cargo run --example all_transactions
```
Demonstrates:
- Legacy P2PKH and P2SH
- SegWit P2WPKH and P2WSH
- Taproot P2TR
- Generic trait usage across all types

### Example 2: Advanced Sighash & Timelocks
```bash
cargo run --example sighash_timelocks
```
Shows:
- All 7 sighash flag combinations
- Absolute and relative timelocks
- HTLC implementation
- Crowdfunding transaction
- Payment channel updates

### Example 3: Taproot Features
```bash
cargo run --example taproot
```
Covers:
- Key-path spending
- Script-path spending
- Schnorr signatures
- Taproot tree construction

### Example 4: Legacy Transactions
```bash
cargo run --example legacy_p2sh
```
Demonstrates:
- Legacy P2PKH transactions
- P2SH multisig (2-of-2, 2-of-3)
- Address generation

### Example 5: Performance Comparison
```bash
cargo run --example compare_legacy_segwit
```
Compares:
- Transaction sizes
- Fee efficiency
- Legacy vs SegWit vs Taproot

### Example 6: Bitcoin Core Integration
```bash
cargo run --example bitcoin_core_test
```
Tests integration with Bitcoin Core node.

---

## 🧪 Testing with Bitcoin Core

### Setup Bitcoin Core Regtest
```bash
# Start Bitcoin Core in regtest mode
bitcoind -regtest -daemon -fallbackfee=0.00001

# Create wallet
bitcoin-cli -regtest createwallet "testwallet"

# Generate blocks (need 101 for coinbase maturity)
ADDR=$(bitcoin-cli -regtest getnewaddress)
bitcoin-cli -regtest generatetoaddress 101 $ADDR

# Verify balance
bitcoin-cli -regtest getbalance
# Should show: 50.00000000
```

### Run Integration Tests
```bash
# Make script executable
chmod +x scripts/bitcoin_core_integration.sh

# Run automated tests
./scripts/bitcoin_core_integration.sh
```

### Manual Testing Workflow

**1. Generate Address**
```bash
cargo run --example all_transactions
# Note the generated address
```

**2. Fund Address**
```bash
TXID=$(bitcoin-cli -regtest sendtoaddress bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw 2.0)
bitcoin-cli -regtest generatetoaddress 1 $ADDR
```

**3. Get UTXO Details**
```bash
# View transaction
bitcoin-cli -regtest getrawtransaction $TXID true

# Or list all UTXOs
bitcoin-cli -regtest listunspent
```

**4. Create & Sign Transaction** (in Rust)
```rust
// Sign transaction with correct input value
let signed = tx.sign_with_traits(&[privkey]).unwrap();
println!("{}", hex::encode(&signed));
```

**5. Broadcast**
```bash
# Test validity
bitcoin-cli -regtest testmempoolaccept '["<hex>"]'

# Broadcast
bitcoin-cli -regtest sendrawtransaction <hex>

# Mine block
bitcoin-cli -regtest generatetoaddress 1 $ADDR
```

---

## 📖 Project Structure

```
bitcoin-tx-rust/
├── src/
│   ├── lib.rs                      # Main library file
│   │
│   ├── traits/                     # Trait system
│   │   ├── mod.rs
│   │   └── transaction.rs          # Core transaction traits
│   │
│   ├── legacy/                     # Legacy transactions
│   │   ├── mod.rs
│   │   ├── p2pkh.rs               # P2PKH implementation
│   │   └── p2sh.rs                # P2SH multisig
│   │
│   ├── segwit/                     # SegWit transactions
│   │   ├── mod.rs
│   │   ├── p2wpkh_single_input.rs # Single input P2WPKH
│   │   ├── p2wpkh_multi_input.rs  # Multi-input P2WPKH
│   │   └── p2wsh.rs               # P2WSH multisig
│   │
│   ├── taproot/                    # Taproot transactions
│   │   ├── mod.rs
│   │   ├── p2tr.rs                # P2TR implementation
│   │   ├── schnorr.rs             # BIP-340 Schnorr
│   │   └── taptree.rs             # Taproot script tree
│   │
│   ├── flags/                      # Sighash flags
│   │   ├── mod.rs
│   │   └── sighash.rs             # Sighash flag definitions
│   │
│   ├── timelocks/                  # Timelock support
│   │   ├── mod.rs
│   │   └── timelocks.rs           # nLockTime & nSequence
│   │
│   └── utils/                      # Utilities
│       ├── mod.rs
│       ├── crypto.rs              # Hash functions
│       ├── keys.rs                # Key management
│       └── address.rs             # Address encoding
│
├── examples/
│   ├── all_transactions.rs         # Comprehensive demo
│   ├── sighash_timelocks.rs       # Advanced features
│   ├── taproot.rs                 # Taproot examples
│   ├── legacy_p2sh.rs             # Legacy examples
│   ├── compare_legacy_segwit.rs   # Performance comparison
│   └── bitcoin_core_test.rs       # Bitcoin Core integration
│
├── scripts/
│   └── bitcoin_core_integration.sh # Automated testing
│
├── Cargo.toml                      # Dependencies
└── README.md                       # This file
```

---

## 🎯 Use Cases & Patterns

### 1. Standard Payment
```rust
use bitcoin_tx_rust::segwit::P2WPKHTransaction;

let mut tx = P2WPKHTransaction::new();
tx.add_input(input);
tx.add_output(output);
let signed = tx.sign(&[privkey])?;
```

### 2. Multisig Wallet (2-of-3)
```rust
use bitcoin_tx_rust::segwit::P2WSHMultisigTransaction;

// Create 2-of-3 redeem script
let script = P2WSHMultisigTransaction::create_multisig_redeem_script(
    2,
    &[pubkey1, pubkey2, pubkey3]
)?;

let mut tx = P2WSHMultisigTransaction::new(script);
tx.add_input(input);
tx.add_output(output);

// Sign with any 2 keys
let signed = tx.sign(&[privkey1, privkey2])?;
```

### 3. Payment Channel Update
```rust
use bitcoin_tx_rust::prelude::*;

let mut channel = MultiInputP2WPKHTransactionWithTraits::new();

// Each party signs only their output with SINGLE
channel.set_sighash_flag(0, SighashFlag::Single)?;
channel.set_sighash_flag(1, SighashFlag::Single)?;
```

### 4. Escrow with Timelock
```rust
use bitcoin_tx_rust::prelude::*;

let mut escrow = P2WSHMultisigTransactionWithTraits::new(script);

// Funds locked until block 800000
escrow.set_locktime(LockTime::BlockHeight(800000));

// Requires 144 blocks to pass
escrow.set_sequence(0, Sequence::from_blocks(144))?;
```

---

## 🛠️ Useful Commands

### Transaction Commands
```bash
# Decode transaction
bitcoin-cli -regtest decoderawtransaction <hex>

# Test validity
bitcoin-cli -regtest testmempoolaccept '["<hex>"]'

# Broadcast
bitcoin-cli -regtest sendrawtransaction <hex>

# View transaction
bitcoin-cli -regtest getrawtransaction <txid> true
```

### Wallet Commands
```bash
# Check balance
bitcoin-cli -regtest getbalance

# List UTXOs
bitcoin-cli -regtest listunspent

# Get new address
bitcoin-cli -regtest getnewaddress

# Send funds
bitcoin-cli -regtest sendtoaddress <address> <amount>
```

### Blockchain Commands
```bash
# Get blockchain info
bitcoin-cli -regtest getblockchaininfo

# Generate blocks
bitcoin-cli -regtest generatetoaddress <n> <address>

# Get current block height
bitcoin-cli -regtest getblockcount
```

---

## 🐛 Troubleshooting

### Common Issues

**"Insufficient funds"**
```bash
# Generate more blocks
bitcoin-cli -regtest generatetoaddress 10 $(bitcoin-cli -regtest getnewaddress)
```

**"Bad-txns-inputs-missingorspent"**
- Verify TXID is correct
- Check vout index matches your address
- Ensure UTXO hasn't been spent
- Confirm transaction is mined (not in mempool)

**"Signature verification failed"**
- Input value must exactly match UTXO value
- Verify using correct private key
- Check sighash flag is valid for transaction type
- Use `decoderawtransaction` to inspect structure

**Build Errors**
```bash
cargo clean
cargo update
cargo build
```

**Reset Bitcoin Core**
```bash
bitcoin-cli -regtest stop
rm -rf ~/.bitcoin/regtest
bitcoind -regtest -daemon
bitcoin-cli -regtest createwallet "testwallet"
```

---

## 📊 Transaction Type Comparison

| Feature | Legacy P2PKH | P2SH | P2WPKH | P2WSH | Taproot |
|---------|-------------|------|--------|-------|---------|
| **Size (vBytes)** | ~226 | ~297 | ~141 | ~169 | ~154 |
| **Fee Efficiency** | ⚠️ Low | ⚠️ Low | ✅ High | ✅ High | ✅ Highest |
| **Malleability** | ❌ Vulnerable | ❌ Vulnerable | ✅ Fixed | ✅ Fixed | ✅ Fixed |
| **Privacy** | ⚠️ Low | ⚠️ Low | ⚠️ Medium | ⚠️ Medium | ✅ High |
| **Multisig** | ❌ No | ✅ Yes | ❌ No | ✅ Yes | ✅ Yes |
| **Schnorr** | ❌ No | ❌ No | ❌ No | ❌ No | ✅ Yes |

**Recommendation**: Use **Taproot** for new applications, **P2WSH** for multisig, **P2WPKH** for simple payments.

---

## 📚 Resources

### Bitcoin Documentation
- [Bitcoin Core RPC Docs](https://developer.bitcoin.org/reference/rpc/)
- [Bitcoin Developer Guide](https://developer.bitcoin.org/devguide/)
- [Mastering Bitcoin (Book)](https://github.com/bitcoinbook/bitcoinbook)

### BIPs (Bitcoin Improvement Proposals)
- [BIP-16: P2SH](https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki)
- [BIP-141: SegWit](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
- [BIP-143: Transaction Signatures](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki)
- [BIP-173: Bech32](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki)
- [BIP-340: Schnorr Signatures](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
- [BIP-341: Taproot](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
- [BIP-342: Taproot Scripts](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki)

### Rust Bitcoin Libraries
- [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin)
- [BDK (Bitcoin Dev Kit)](https://github.com/bitcoindevkit/bdk)
- [rust-secp256k1](https://github.com/rust-bitcoin/rust-secp256k1)

---

## 🤝 Contributing

Contributions are welcome! This is an educational project aimed at helping developers understand Bitcoin transactions.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Add tests for new features
4. Ensure all tests pass (`cargo test`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

---

## 📄 License

This project is licensed under:
- Apache License 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

---

## 🙏 Acknowledgments

- Bitcoin Core developers for their excellent work
- Rust Bitcoin community for the foundational libraries
- BIP authors for detailed specifications
- Educational resources: Mastering Bitcoin, Learn Me a Bitcoin

---

## 🆘 Support & Community

- **Issues**: [GitHub Issues](https://github.com/cenwadike/bitcoin_tx_rust/issues)
- **Discussions**: [GitHub Discussions](https://github.com/cenwadike/bitcoin_tx_rust/discussions)
- **Documentation**: Run `cargo doc --open` for API docs

---

## ⚠️ Security Notice

This library is designed for educational purposes and research. While the code follows best practices:

- ⚠️ Conduct your own security review before production use
- ⚠️ Never use test private keys in production
- ⚠️ Always verify transactions before broadcasting
- ⚠️ Use hardware wallets for significant amounts
- ⚠️ Test thoroughly in regtest/testnet before mainnet

---

## 🗺️ Roadmap

- [ ] PSBT (Partially Signed Bitcoin Transactions) support
- [ ] Hardware wallet integration
- [ ] Performance benchmarks
- [ ] Fuzzing tests

---

**Built with ❤️ for the Bitcoin community**

Happy Bitcoin developing! 🚀⚡