//! Legacy P2SH Multisig Transaction Example
//!
//! This demonstrates creating a P2SH (Pay-to-Script-Hash) multisig transaction
//! in the legacy (pre-SegWit) format.

use bitcoin_tx_rust::*;

fn main() {
    println!("=== Legacy P2SH Multisig Transaction Example ===\n");

    example_2of2_p2sh();
    example_2of3_p2sh();
}

fn example_2of2_p2sh() {
    println!("1. Creating a 2-of-2 P2SH Multisig Transaction");
    println!("----------------------------------------------");

    // Create three private keys
    let privkey1 = [0x11u8; 32];
    let privkey2 = [0x22u8; 32];

    // Derive public keys
    let pubkey1 = privkey_to_pubkey(&privkey1).unwrap();
    let pubkey2 = privkey_to_pubkey(&privkey2).unwrap();

    println!("Public key 1: {}", hex::encode(&pubkey1));
    println!("Public key 2: {}", hex::encode(&pubkey2));

    // Create 2-of-2 multisig redeem script
    let redeem_script =
        legacy::P2SHMultisigTransaction::create_2of2_redeem_script(&pubkey1, &pubkey2);

    println!("\nRedeem script: {}", hex::encode(&redeem_script));
    println!("Redeem script length: {} bytes", redeem_script.len());

    // Convert to P2SH address
    let p2sh_address = legacy::P2SHMultisigTransaction::script_to_p2sh(&redeem_script, "regtest");
    println!("P2SH address: {}", p2sh_address);

    // This address can now be funded using:
    // bitcoin-cli -regtest sendtoaddress <address> 2.001

    println!("\n--- Creating spending transaction ---");

    // Create transaction spending from the multisig
    let mut tx = legacy::P2SHMultisigTransaction::new(redeem_script);

    // Simulated funding TXID (would be real in production)
    let funding_txid = [
        0x70, 0xcf, 0xb9, 0x92, 0xf5, 0x2c, 0x4f, 0xc5, 0x17, 0xf7, 0xde, 0xa0, 0x10, 0xf5, 0x95,
        0x7e, 0x07, 0xa0, 0x03, 0x48, 0x15, 0x55, 0x35, 0x4e, 0xa7, 0x22, 0x87, 0xd1, 0x3f, 0xc3,
        0x60, 0x2a,
    ];

    tx.add_input(TxInput::new(funding_txid, 0));

    // Output 1: Send 1.5 BTC to receiver
    let receiver_spk = hex::decode("76a9143bc28d6d92d9073fb5e3adf481795eaf446bceed88ac").unwrap();
    tx.add_output(TxOutput::new(150_000_000, receiver_spk));

    // Output 2: Send 0.5 BTC change
    let change_spk = hex::decode("76a914cc1b07838e387deacd0e5232e1e8b49f4c29e48488ac").unwrap();
    tx.add_output(TxOutput::new(50_000_000, change_spk));

    // Build unsigned transaction
    let unsigned = tx.build_unsigned();
    println!("Unsigned transaction: {}", hex::encode(&unsigned));

    // Sign with both private keys
    let signed_tx = tx.sign(&[privkey1, privkey2], 0).unwrap();
    println!("\nSigned transaction: {}", hex::encode(&signed_tx));
    println!("Transaction size: {} bytes", signed_tx.len());

    println!("\nTo broadcast:");
    println!(
        "  bitcoin-cli -regtest sendrawtransaction {}",
        hex::encode(&signed_tx)
    );
}

fn example_2of3_p2sh() {
    println!("\n\n2. Creating a 2-of-3 P2SH Multisig Transaction");
    println!("----------------------------------------------");

    // Create three private keys
    let privkey1 = [0x11u8; 32];
    let privkey2 = [0x22u8; 32];
    let privkey3 = [0x33u8; 32];

    // Derive public keys
    let pubkey1 = privkey_to_pubkey(&privkey1).unwrap();
    let pubkey2 = privkey_to_pubkey(&privkey2).unwrap();
    let pubkey3 = privkey_to_pubkey(&privkey3).unwrap();

    println!("Public key 1: {}", hex::encode(&pubkey1));
    println!("Public key 2: {}", hex::encode(&pubkey2));
    println!("Public key 3: {}", hex::encode(&pubkey3));

    // Create 2-of-3 multisig redeem script
    let redeem_script =
        legacy::P2SHMultisigTransaction::create_2of3_redeem_script(&pubkey1, &pubkey2, &pubkey3);

    println!("\nRedeem script: {}", hex::encode(&redeem_script));
    println!("Redeem script structure:");
    println!("  OP_2 (0x52): Requires 2 signatures");
    println!("  <pubkey1>");
    println!("  <pubkey2>");
    println!("  <pubkey3>");
    println!("  OP_3 (0x53): Total of 3 public keys");
    println!("  OP_CHECKMULTISIG (0xae)");

    // Convert to P2SH address
    let p2sh_address = legacy::P2SHMultisigTransaction::script_to_p2sh(&redeem_script, "regtest");
    println!("\nP2SH address: {}", p2sh_address);
    println!(
        "Fund this address with: bitcoin-cli -regtest sendtoaddress {} 2.001",
        p2sh_address
    );

    println!("\n--- Creating spending transaction (using 2 of 3 keys) ---");

    // Create transaction
    let mut tx = legacy::P2SHMultisigTransaction::new(redeem_script);

    // Simulated funding TXID
    let funding_txid = [
        0x70, 0xcf, 0xb9, 0x92, 0xf5, 0x2c, 0x4f, 0xc5, 0x17, 0xf7, 0xde, 0xa0, 0x10, 0xf5, 0x95,
        0x7e, 0x07, 0xa0, 0x03, 0x48, 0x15, 0x55, 0x35, 0x4e, 0xa7, 0x22, 0x87, 0xd1, 0x3f, 0xc3,
        0x60, 0x2a,
    ];

    tx.add_input(TxInput::new(funding_txid, 0));

    // Outputs
    let receiver_spk = hex::decode("76a9143bc28d6d92d9073fb5e3adf481795eaf446bceed88ac").unwrap();
    tx.add_output(TxOutput::new(150_000_000, receiver_spk));

    let change_spk = hex::decode("76a914cc1b07838e387deacd0e5232e1e8b49f4c29e48488ac").unwrap();
    tx.add_output(TxOutput::new(50_000_000, change_spk));

    // Sign with first 2 keys only (we only need 2 of 3)
    println!("\nSigning with private keys 1 and 2 (key 3 not needed)...");
    let signed_tx = tx.sign(&[privkey1, privkey2], 0).unwrap();

    println!("Signed transaction: {}", hex::encode(&signed_tx));
    println!("Transaction size: {} bytes", signed_tx.len());

    println!("\n✓ Successfully created 2-of-3 multisig transaction!");
    println!("Note: Any 2 of the 3 keys can be used to sign");
}
