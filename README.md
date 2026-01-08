# Bitcoin Transaction Rust Library

A comprehensive educational library for creating and signing Bitcoin transactions in Rust.

## Features

- ✅ **SegWit Transactions**: P2WPKH single/multiple inputs, P2WSH multisig (2-of-2, M-of-N)
- ✅ **Legacy Transactions**: P2PKH, P2SH multisig (2-of-2, 2-of-3, M-of-N)
- ✅ **Full BIP Support**: BIP141 (SegWit), BIP143 (signing), BIP173 (Bech32)
- ✅ **Bitcoin Core Integration**: Works with regtest mode for testing
- ✅ **Educational**: Well-documented code with comprehensive examples

⚠️ **For educational purposes only** - Not intended for production use without security review.

---

## Quick Setup

### 1. Install Dependencies
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Install Bitcoin Core (Ubuntu/Debian)
sudo add-apt-repository ppa:bitcoin/bitcoin
sudo apt-get update
sudo apt-get install bitcoind bitcoin-cli

# Or macOS
brew install bitcoin
```

### 2. Build the Project
```bash
cd bitcoin-tx-rust
cargo build --release
```

### 3. Run Tests
```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture
```

---

## Running Examples

### Example 1: All Transaction Types
```bash
cargo run --example all_transactions
```

Shows examples of:
- P2WPKH single input
- P2WPKH multiple inputs
- P2WSH 2-of-2 multisig
- P2WSH 3-of-5 multisig
- Legacy P2SH multisig

### Example 2: Legacy P2SH Multisig
```bash
cargo run --example legacy_p2sh
```

Demonstrates legacy P2SH 2-of-2 and 2-of-3 multisig transactions.

### Example 3: Legacy vs SegWit Comparison
```bash
cargo run --example compare_legacy_segwit
```

Compares transaction sizes and fees between legacy and SegWit.

### Example 4: Bitcoin Core Integration
```bash
cargo run --example bitcoin_core_test
```

Tests integration with a running Bitcoin Core node.

---

## Testing with Bitcoin Core

### Start Bitcoin Core
```bash
# Start in regtest mode
bitcoind -regtest -daemon -fallbackfee=0.00001

# Create wallet
bitcoin-cli -regtest createwallet "testwallet"

# Generate 101 blocks for testing
ADDR=$(bitcoin-cli -regtest getnewaddress)
bitcoin-cli -regtest generatetoaddress 101 $ADDR

# Verify setup
bitcoin-cli -regtest getbalance
# Should show: 50.00000000
```

### Run Integration Script
```bash
# Make executable
chmod +x scripts/bitcoin_core_integration.sh

# Run automated tests
./scripts/bitcoin_core_integration.sh
```

This script will:
1. Check Bitcoin Core is running
2. Create and fund test addresses
3. Show how to verify transactions
4. Provide helpful commands for manual testing

---

## Complete Workflow Example

### 1. Generate Address
```rust
use bitcoin_tx_rust::*;

let privkey = [0x11u8; 32];
let pubkey = privkey_to_pubkey(&privkey).unwrap();
let address = pk_to_p2wpkh(&pubkey, "regtest").unwrap();
// Output: bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw
```

### 2. Fund the Address
```bash
TXID=$(bitcoin-cli -regtest sendtoaddress bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw 2.001)
bitcoin-cli -regtest generatetoaddress 1 $ADDR
```

### 3. Get UTXO Details
```bash
# Get transaction details
RAW=$(bitcoin-cli -regtest getrawtransaction $TXID)
bitcoin-cli -regtest decoderawtransaction $RAW

# Note the vout index where your address appears
```

### 4. Create & Sign Transaction
```rust
// Create transaction
let mut tx = P2WPKHTransaction::new();
tx.add_input(TxInput::new(txid, vout_index));

// Add outputs
let receiver_spk = bech32_to_spk("bcrt", "bcrt1q6mlqttg852e63uahyglwla55xusryqp08vx9w2").unwrap();
tx.add_output(TxOutput::new(150_000_000, receiver_spk)); // 1.5 BTC

let change_spk = bech32_to_spk("bcrt", "bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw").unwrap();
tx.add_output(TxOutput::new(50_000_000, change_spk)); // 0.5 BTC change

// Sign (input value must match UTXO value)
let signed = tx.sign(&privkey, &pubkey, 200_100_000).unwrap();
println!("{}", hex::encode(&signed));
```

### 5. Broadcast Transaction
```bash
# Test if valid (doesn't broadcast)
bitcoin-cli -regtest testmempoolaccept '["<hex>"]'

# Broadcast
bitcoin-cli -regtest sendrawtransaction <hex>

# Confirm
bitcoin-cli -regtest generatetoaddress 1 $ADDR
```

---

## Useful Commands

### Transaction Management
```bash
# Decode transaction
bitcoin-cli -regtest decoderawtransaction <hex>

# Test transaction validity
bitcoin-cli -regtest testmempoolaccept '["<hex>"]'

# Broadcast transaction
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

# Send to address
bitcoin-cli -regtest sendtoaddress <address> <amount>
```

### Blockchain Commands
```bash
# Get blockchain info
bitcoin-cli -regtest getblockchaininfo

# Generate blocks
bitcoin-cli -regtest generatetoaddress <n> <address>

# Get block count
bitcoin-cli -regtest getblockcount
```

---

## Troubleshooting

### "Insufficient funds"
```bash
bitcoin-cli -regtest generatetoaddress 10 $(bitcoin-cli -regtest getnewaddress)
```

### "Bad-txns-inputs-missingorspent"
- Verify TXID is correct
- Check vout index matches your address
- Ensure UTXO hasn't been spent
- Confirm transaction is mined

### "Signature verification failed"
- Input value must exactly match UTXO value
- Verify using correct private key
- Check transaction structure with `decoderawtransaction`

### Build Errors
```bash
cargo clean
cargo update
cargo build
```

### Reset Bitcoin Core
```bash
bitcoin-cli -regtest stop
rm -rf ~/.bitcoin/regtest
bitcoind -regtest -daemon
bitcoin-cli -regtest createwallet "testwallet"
```

---

## Project Structure
```
bitcoin-tx-rust/
├── Cargo.toml              # Library configuration
├── README.md               # This file
├── src/
│   ├── lib.rs              # Main library
│   ├── utils/              # Crypto, keys, addresses
│   ├── p2wpkh/             # SegWit P2WPKH transactions
│   ├── multisig/           # SegWit P2WSH multisig
│   └── legacy/             # Legacy P2PKH/P2SH
├── examples/
│   ├── all_transactions.rs
│   ├── bitcoin_core_test.rs
│   ├── legacy_p2sh.rs
│   └── compare_legacy_segwit.rs
└── scripts/
    └── bitcoin_core_integration.sh
```

---

## Use as Library

Add to your `Cargo.toml`:
```toml
[dependencies]
bitcoin-tx-rust = { path = "../bitcoin-tx-rust" }
```

Use in your code:
```rust
use bitcoin_tx_rust::*;

fn main() {
    let privkey = generate_privkey();
    let pubkey = privkey_to_pubkey(&privkey).unwrap();
    let address = pk_to_p2wpkh(&pubkey, "regtest").unwrap();
    println!("Address: {}", address);
}
```

---

## Cleanup
```bash
# Stop Bitcoin Core
bitcoin-cli -regtest stop

# Remove test data (optional)
rm -rf ~/.bitcoin/regtest

# Clean build artifacts
cargo clean
```

---

## Resources

- [Bitcoin Core RPC Docs](https://developer.bitcoin.org/reference/rpc/)
- [BIP141: Segregated Witness](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
- [BIP143: Transaction Signatures](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki)
- [BIP173: Bech32 Addresses](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki)

---

## License

MIT OR Apache-2.0

## Contributing

This is an educational project. Contributions, issues, and feature requests are welcome!

---

**Happy Bitcoin developing! 🚀**
