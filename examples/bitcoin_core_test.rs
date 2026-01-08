//! Bitcoin Core Integration Test
//!
//! This example demonstrates how to create transactions that can be broadcast
//! to a local Bitcoin Core node running in regtest mode.
//!
//! Prerequisites:
//! 1. Bitcoin Core installed
//! 2. Run: bitcoind -regtest -daemon
//! 3. Create wallet: bitcoin-cli -regtest createwallet "test"
//! 4. Generate blocks: bitcoin-cli -regtest generatetoaddress 101 $(bitcoin-cli -regtest getnewaddress)

use bitcoin_tx_rust::*;
use std::process::Command;

fn main() {
    println!("=== Bitcoin Core Integration Test ===\n");

    // Check if Bitcoin Core is running
    if !check_bitcoin_core() {
        eprintln!("Error: Bitcoin Core not running in regtest mode");
        eprintln!("Start it with: bitcoind -regtest -daemon");
        return;
    }

    println!("✓ Bitcoin Core is running\n");

    // Example 1: Create and fund a P2WPKH address
    example_create_and_fund_p2wpkh();

    // Example 2: Spend from a funded address
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
    println!("Example 1: Create and Fund P2WPKH Address");
    println!("==========================================\n");

    // Generate keys
    let privkey = [0x11u8; 32];
    let pubkey = privkey_to_pubkey(&privkey).unwrap();
    let address = pk_to_p2wpkh(&pubkey, "regtest").unwrap();

    println!("Generated address: {}", address);
    println!("Private key: {}", hex::encode(&privkey));
    println!("Public key: {}", hex::encode(&pubkey));

    // Fund the address
    println!("\nFunding address with 2.001 BTC...");
    match bitcoin_cli(&["sendtoaddress", &address, "2.001"]) {
        Ok(txid) => {
            println!("✓ Funded! TXID: {}", txid);

            // Mine a block to confirm
            match bitcoin_cli(&["getnewaddress"]) {
                Ok(mining_addr) => match bitcoin_cli(&["generatetoaddress", "1", &mining_addr]) {
                    Ok(_) => println!("✓ Transaction confirmed"),
                    Err(e) => println!("Warning: Could not mine block: {}", e),
                },
                Err(e) => println!("Warning: Could not get mining address: {}", e),
            }

            // Get transaction details
            println!("\nTransaction details:");
            if let Ok(raw_tx) = bitcoin_cli(&["getrawtransaction", &txid]) {
                if let Ok(decoded) = bitcoin_cli(&["decoderawtransaction", &raw_tx]) {
                    // Parse and find our output
                    println!("{}", decoded);
                }
            }
        }
        Err(e) => {
            println!("Error funding address: {}", e);
            println!("Make sure you have:");
            println!("  1. Created a wallet: bitcoin-cli -regtest createwallet \"test\"");
            println!(
                "  2. Generated blocks: bitcoin-cli -regtest generatetoaddress 101 $(bitcoin-cli -regtest getnewaddress)"
            );
        }
    }
}

#[allow(dead_code)]
fn example_spend_p2wpkh() {
    println!("\n\nExample 2: Spend from P2WPKH Address");
    println!("======================================\n");

    // This would use actual UTXO from Bitcoin Core
    let sender_privkey = [0x11u8; 32];
    let sender_pubkey = privkey_to_pubkey(&sender_privkey).unwrap();

    // Create transaction (you'd need to get real UTXO info from Bitcoin Core)
    let mut tx = P2WPKHTransaction::new();

    // Example TXID (replace with real one)
    let txid_hex = "0000000000000000000000000000000000000000000000000000000000000000";
    let mut txid = [0u8; 32];
    hex::decode_to_slice(txid_hex, &mut txid).unwrap();

    tx.add_input(TxInput::new(txid, 0));

    // Receiver address
    let receiver_address = "bcrt1q6mlqttg852e63uahyglwla55xusryqp08vx9w2";
    let receiver_spk = bech32_to_spk("bcrt", receiver_address).unwrap();
    tx.add_output(TxOutput::new(100_000_000, receiver_spk));

    // Change
    let change_pk_hash = hash160(&sender_pubkey);
    let mut change_spk = vec![0x00, 0x14];
    change_spk.extend_from_slice(&change_pk_hash);
    tx.add_output(TxOutput::new(99_900_000, change_spk));

    // Sign
    let signed_tx = tx
        .sign(&sender_privkey, &sender_pubkey, 200_000_000)
        .unwrap();
    let tx_hex = hex::encode(&signed_tx);

    println!("Signed transaction: {}", tx_hex);
    println!("\nTo broadcast:");
    println!("  bitcoin-cli -regtest sendrawtransaction {}", tx_hex);
}
