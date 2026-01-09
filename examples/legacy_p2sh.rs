//! examples/legacy_p2sh.rs
//!
//! Demonstrates creating and signing legacy P2SH (Pay-to-Script-Hash) multisig transactions:
//!   • 2-of-2 multisig
//!   • 2-of-3 multisig (using only 2 keys to spend)

use bitcoin_tx_rust::*;

fn main() {
    println!("=== Legacy P2SH Multisig Transaction Examples ===\n");

    example_2of2_p2sh();
    example_2of3_p2sh();
}

fn example_2of2_p2sh() {
    println!("1. 2-of-2 P2SH Multisig");
    println!("---------------------");

    let privkey1 = [0x11u8; 32];
    let privkey2 = [0x22u8; 32];

    let pubkey1 = privkey_to_pubkey(&privkey1).unwrap();
    let pubkey2 = privkey_to_pubkey(&privkey2).unwrap();

    println!("Public key 1: {}", hex::encode(&pubkey1));
    println!("Public key 2: {}", hex::encode(&pubkey2));

    let redeem_script =
        legacy::P2SHMultisigTransaction::create_2of2_redeem_script(&pubkey1, &pubkey2);
    println!("\nRedeem script: {}", hex::encode(&redeem_script));

    let p2sh_address = legacy::P2SHMultisigTransaction::script_to_p2sh(&redeem_script, "regtest");
    println!("P2SH address: {}", p2sh_address);

    println!("\nCreating spending tx...");

    let mut tx = legacy::P2SHMultisigTransaction::new(redeem_script);

    // Funding UTXO (simulated)
    let funding_txid = [
        0x70, 0xcf, 0xb9, 0x92, 0xf5, 0x2c, 0x4f, 0xc5, 0x17, 0xf7, 0xde, 0xa0, 0x10, 0xf5, 0x95,
        0x7e, 0x07, 0xa0, 0x03, 0x48, 0x15, 0x55, 0x35, 0x4e, 0xa7, 0x22, 0x87, 0xd1, 0x3f, 0xc3,
        0x60, 0x2a,
    ];

    // Correct add_input: txid, vout, amount
    tx.add_input(funding_txid, 0, 200_000_000);

    // Receiver output
    let receiver_spk = hex::decode("76a9143bc28d6d92d9073fb5e3adf481795eaf446bceed88ac").unwrap();
    tx.add_output(150_000_000, receiver_spk);

    // Change output
    let change_spk = hex::decode("76a914cc1b07838e387deacd0e5232e1e8b49f4c29e48488ac").unwrap();
    tx.add_output(50_000_000, change_spk);

    // Sign (pass vector of key sets — one vec per input)
    let signing_keys = vec![vec![privkey1, privkey2]]; // single input, needs both keys

    let signed_tx = tx.sign(&signing_keys).unwrap();

    println!("Signed tx size: {} bytes", signed_tx.len());
    println!("Signed tx hex: {}", hex::encode(&signed_tx));

    println!(
        "\nTo broadcast: bitcoin-cli -regtest sendrawtransaction {}\n",
        hex::encode(&signed_tx)
    );
}

fn example_2of3_p2sh() {
    println!("2. 2-of-3 P2SH Multisig (spend with only 2 keys)");
    println!("--------------------------------------------");

    let privkey1 = [0x11u8; 32];
    let privkey2 = [0x22u8; 32];
    let privkey3 = [0x33u8; 32];

    let pubkey1 = privkey_to_pubkey(&privkey1).unwrap();
    let pubkey2 = privkey_to_pubkey(&privkey2).unwrap();
    let pubkey3 = privkey_to_pubkey(&privkey3).unwrap();

    let redeem_script =
        legacy::P2SHMultisigTransaction::create_2of3_redeem_script(&pubkey1, &pubkey2, &pubkey3);
    println!("\nRedeem script: {}", hex::encode(&redeem_script));

    let p2sh_address = legacy::P2SHMultisigTransaction::script_to_p2sh(&redeem_script, "regtest");
    println!("P2SH address: {}", p2sh_address);

    println!("\nCreating spending tx...");

    let mut tx = legacy::P2SHMultisigTransaction::new(redeem_script);

    let funding_txid = [
        0x70, 0xcf, 0xb9, 0x92, 0xf5, 0x2c, 0x4f, 0xc5, 0x17, 0xf7, 0xde, 0xa0, 0x10, 0xf5, 0x95,
        0x7e, 0x07, 0xa0, 0x03, 0x48, 0x15, 0x55, 0x35, 0x4e, 0xa7, 0x22, 0x87, 0xd1, 0x3f, 0xc3,
        0x60, 0x2a,
    ];

    tx.add_input(funding_txid, 0, 200_000_000);

    let receiver_spk = hex::decode("76a9143bc28d6d92d9073fb5e3adf481795eaf446bceed88ac").unwrap();
    tx.add_output(150_000_000, receiver_spk);

    let change_spk = hex::decode("76a914cc1b07838e387deacd0e5232e1e8b49f4c29e48488ac").unwrap();
    tx.add_output(50_000_000, change_spk);

    // Sign with only 2 keys (2-of-3 — we don't need the 3rd)
    let signing_keys = vec![vec![privkey1, privkey2]];

    let signed_tx = tx.sign(&signing_keys).unwrap();

    println!("Signed tx size: {} bytes", signed_tx.len());
    println!("Signed tx hex: {}", hex::encode(&signed_tx));

    println!("\n✓ 2-of-3 multisig spending successful using only 2 keys!\n");
}
