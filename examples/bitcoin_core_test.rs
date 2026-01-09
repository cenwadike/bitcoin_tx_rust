//! examples/bitcoin_core_test.rs
//!
//! Integration test: Create & broadcast real transactions to local Bitcoin Core regtest
//!
//! Prerequisites:
//! 1. bitcoind -regtest -daemon
//! 2. bitcoin-cli -regtest createwallet "test"
//! 3. bitcoin-cli -regtest generatetoaddress 101 $(bitcoin-cli -regtest getnewaddress)

use bitcoin_tx_rust::*;
use std::process::Command;

fn main() {
    println!("=== Bitcoin Core Integration Test (Regtest) ===\n");

    if !check_bitcoin_core() {
        eprintln!("Error: Bitcoin Core not running in regtest mode");
        eprintln!("Start it with: bitcoind -regtest -daemon");
        return;
    }

    println!("✓ Bitcoin Core is running\n");

    example_create_and_fund_p2wpkh();

    // Uncomment once you have real UTXO data from 'listunspent'
    // example_spend_p2wpkh();
}

fn check_bitcoin_core() -> bool {
    let output = Command::new("bitcoin-cli")
        .args(&["-regtest", "getblockchaininfo"])
        .output();

    match output {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

fn bitcoin_cli(args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let mut cmd_args = vec!["-regtest"];
    cmd_args.extend_from_slice(args);

    let output = Command::new("bitcoin-cli").args(&cmd_args).output()?;

    if !output.status.success() {
        return Err(format!(
            "bitcoin-cli failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

fn example_create_and_fund_p2wpkh() {
    println!("Example 1: Create & Fund Native P2WPKH Address");
    println!("==============================================\n");

    let privkey = [0x11u8; 32];
    let pubkey = privkey_to_pubkey(&privkey).unwrap();
    let address = pk_to_p2wpkh(&pubkey, "regtest").unwrap();

    println!("Generated address: {}", address);
    println!("Private key (hex): {}", hex::encode(&privkey));
    println!("Public key (hex): {}", hex::encode(&pubkey));

    println!("\nFunding address with 2.001 BTC...");
    match bitcoin_cli(&["sendtoaddress", &address, "2.001"]) {
        Ok(txid) => {
            println!("✓ Funded! TXID: {}", txid);

            // Mine 1 block to confirm
            match bitcoin_cli(&["getnewaddress"]) {
                Ok(mining_addr) => {
                    let _ = bitcoin_cli(&["generatetoaddress", "1", &mining_addr]);
                    println!("✓ Mined 1 block → transaction confirmed");
                }
                Err(e) => println!("Warning: Could not mine block: {}", e),
            }
        }
        Err(e) => {
            println!("Error funding address: {}", e);
            println!("\nFixes:");
            println!("  bitcoin-cli -regtest createwallet \"test\"");
            println!(
                "  bitcoin-cli -regtest generatetoaddress 101 $(bitcoin-cli -regtest getnewaddress)"
            );
        }
    }
}
#[allow(dead_code)]
fn example_spend_p2wpkh() {
    println!("\nExample 2: Spend from Funded P2WPKH Address");
    println!("==========================================\n");

    let sender_privkey = [0x11u8; 32];
    let sender_pubkey = privkey_to_pubkey(&sender_privkey).unwrap();

    // !!! REPLACE THESE WITH REAL DATA FROM YOUR NODE !!!
    // Command: bitcoin-cli -regtest listunspent
    let real_txid_hex = "REPLACE_WITH_REAL_TXID"; // e.g. "d4ce50311efa12a97b6c910afba180686687edae..."
    let real_vout: u32 = 0; // usually 0 or 1
    let real_amount_sat: u64 = 200_100_000; // must match actual UTXO amount

    // Real input script_pubkey = OP_0 PUSH20 <hash160(pubkey)>
    let input_script_pubkey = vec![
        0x00, 0x14, // OP_0 PUSH20
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, // ← replace with real hash160(pubkey)
    ];

    let mut tx = P2WPKHTransaction::new();

    // Correct order: txid, vout, script_pubkey, amount
    let txid_bytes = hex::decode(real_txid_hex).expect("Invalid txid hex");
    let txid: [u8; 32] = txid_bytes.try_into().expect("Txid must be 32 bytes");

    tx.add_input(txid, real_vout, input_script_pubkey, real_amount_sat);

    // Receiver output
    let receiver_address = "bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw";
    let receiver_spk = bech32_to_spk("bcrt", receiver_address).unwrap();
    tx.add_output(100_000_000, receiver_spk);

    // Change output back to sender
    let change_pk_hash = hash160(&sender_pubkey);
    let mut change_spk = vec![0x00, 0x14];
    change_spk.extend_from_slice(&change_pk_hash);
    tx.add_output(99_900_000, change_spk);

    // Sign (single input → single key)
    let signed_tx = tx.sign(&[sender_privkey]).unwrap();
    let tx_hex = hex::encode(&signed_tx);

    println!("Signed transaction hex:\n{}", tx_hex);
    println!("Size: {} bytes\n", signed_tx.len());

    println!("To broadcast:");
    println!("  bitcoin-cli -regtest sendrawtransaction {}", tx_hex);
}
