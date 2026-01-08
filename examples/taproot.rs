//! examples/taproot_example.rs
//!
//! Demonstrates Taproot (P2TR) transactions:
//!   • Key-path spend (no script revealed)
//!   • Script-path spend (reveals a simple P2PK script)

use bitcoin_tx_rust::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Taproot Transaction Examples ===\n");

    // ===================================================================
    // 1. Key-Path Spend (most common — no script revealed)
    // ===================================================================
    println!("1. Key-Path Spend (P2TR with no script tree)");
    println!("------------------------------------------------");

    let internal_privkey = [0xB0u8; 32]; // Private key for internal key
    let internal_pubkey = schnorr_pubkey_gen(&internal_privkey)?;

    // Create transaction with no merkle root (key-path only)
    let mut keypath_tx = P2TRKeyPathTransaction::new(internal_pubkey.clone(), None);

    // Add a dummy previous output we're spending
    keypath_tx.add_input(TxInput::new([0x11u8; 32], 0));

    // Send 99_900_000 sats to a dummy P2TR output
    let dummy_output_spk = vec![0x51, 0x20]; // OP_1 OP_PUSHBYTES_32
    let mut dummy_hash = vec![0xAAu8; 32];
    dummy_hash.extend_from_slice(&[]); // 34 bytes total
    keypath_tx.add_output(TxOutput::new(
        99_900_000,
        dummy_output_spk.into_iter().chain(dummy_hash).collect(),
    ));

    // Get the Taproot output public key (tweaked)
    let taproot_pubkey = keypath_tx.get_taproot_pubkey()?;
    println!("   Taproot output pubkey: {}", hex::encode(&taproot_pubkey));

    // Sign using key path
    let input_value = 100_000_000u64;
    let input_scriptpubkey = vec![0x51, 0x20]; // dummy P2TR scriptPubKey prefix + 32-byte key
    let input_scriptpubkey = input_scriptpubkey
        .into_iter()
        .chain(taproot_pubkey.clone())
        .collect();

    let keypath_signed =
        keypath_tx.sign(&internal_privkey, &[input_value], &[input_scriptpubkey])?;

    println!("   Key-path signed tx size: {} bytes", keypath_signed.len());
    println!("   Key-path tx hex: {}\n", hex::encode(&keypath_signed));

    // ===================================================================
    // 2. Script-Path Spend (with a simple Pay-to-PubKey script)
    // ===================================================================
    println!("2. Script-Path Spend (revealing a P2PK script)");
    println!("-----------------------------------------------------");

    // Create a script: <pubkey> OP_CHECKSIG
    let script_privkey = [0xF0u8; 32];
    let script_pubkey = schnorr_pubkey_gen(&script_privkey)?;
    let tapscript = create_p2pk_tapscript(&script_pubkey);

    let leaf = TapLeaf::new(tapscript);

    // Single leaf → merkle root = leaf hash, path is empty, parity from version
    let leaf_hash = leaf.leaf_hash();
    let parity = (leaf.version & 1) == 1;

    // Create script-path transaction
    let mut scriptpath_tx = P2TRScriptPathTransaction::new(
        internal_pubkey.clone(),
        leaf,
        vec![], // empty merkle path (single leaf)
        parity,
    );

    scriptpath_tx.add_input(TxInput::new([0x22u8; 32], 1));
    scriptpath_tx.add_output(TxOutput::new(
        99_800_000,
        [vec![0x76, 0xa9, 0x14], vec![0xBBu8; 17]].concat(),
    ));

    // Get tweaked output key (now includes merkle root)
    let merkle_root = Some(leaf_hash.to_vec());
    let (_, tweaked_pubkey) = taproot_tweak_pubkey(&internal_pubkey, merkle_root.as_deref())?;
    println!(
        "   Tweaked output pubkey (with script): {}",
        hex::encode(&tweaked_pubkey)
    );

    // Sign using script path (use the script's private key)
    let scriptpath_signed = scriptpath_tx.sign(
        &script_privkey,
        &[100_000_000],
        &[vec![0x51, 0x20].into_iter().chain(tweaked_pubkey).collect()],
    )?;

    println!(
        "   Script-path signed tx size: {} bytes",
        scriptpath_signed.len()
    );
    println!(
        "   Script-path tx hex: {}\n",
        hex::encode(&scriptpath_signed)
    );

    // ===================================================================
    // Summary
    // ===================================================================
    println!("Summary:");
    println!("  • Key-path spend: Witness = [64-byte signature]");
    println!("  • Script-path spend: Witness = [signature] [script] [control block]");
    println!("  • Both spend from the same Taproot output (different spending conditions)");

    Ok(())
}
