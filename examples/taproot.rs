//! examples/taproot.rs
//!
//! Demonstrates Taproot (P2TR) transactions using the modern unified TaprootTransaction:
//!   • Key-path spend (no script revealed)
//!   • Script-path spend (reveals a simple P2PK script)

use bitcoin_tx_rust::{address::taproot_address, *};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Taproot Transaction Examples (Unified API) ===\n");

    // ===================================================================
    // 1. Key-Path Spend (most common — no script revealed)
    // ===================================================================
    println!("1. Key-Path Spend (pure key spend, no script tree)");
    println!("---------------------------------------------------");

    let internal_privkey = [0xB0u8; 32];
    let internal_pubkey = schnorr_pubkey_gen(&internal_privkey)?;

    let mut tx = TaprootTransaction::new();

    // Dummy input (real UTXO would have real txid/vout/amount/spk)
    let dummy_input_spk = vec![0x51, 0x20].into_iter().chain([0xAAu8; 32]).collect();
    tx.add_input([0x11u8; 32], 0, 100_000_000, dummy_input_spk);

    // Output (dummy P2TR)
    let output_spk = vec![0x51, 0x20].into_iter().chain([0xAAu8; 32]).collect();
    tx.add_output(99_900_000, output_spk);

    // Configure key-path spend (no merkle root = key-path only)
    tx.set_keypath_spend(0, internal_privkey, None)?;

    // Compute tweaked pubkey (for address and input spk verification)
    let (_parity, tweaked_pubkey) = taproot_tweak_pubkey(&internal_pubkey, None)?;
    let address = taproot_address(&tweaked_pubkey, "regtest")?;
    println!("   Taproot output address: {}", address);

    // Sign
    let signed_tx = tx.sign()?;

    println!("   Key-path signed tx size: {} bytes", signed_tx.len());
    println!(
        "   Key-path tx hex (first 200 chars): {}\n",
        hex::encode(&signed_tx[..200.min(signed_tx.len())])
    );

    // ===================================================================
    // 2. Script-Path Spend (reveals a simple Pay-to-PubKey script)
    // ===================================================================
    println!("2. Script-Path Spend (reveals P2PK tapscript)");
    println!("---------------------------------------------");

    let script_privkey = [0xF0u8; 32];
    let script_pubkey = schnorr_pubkey_gen(&script_privkey)?;
    let tapscript = create_p2pk_tapscript(&script_pubkey);
    let leaf = TapLeaf::new(tapscript);

    let leaf_hash = leaf.leaf_hash();
    let (output_parity, tweaked_pubkey) = taproot_tweak_pubkey(&internal_pubkey, Some(&leaf_hash))?;

    let mut tx = TaprootTransaction::new();

    let input_spk = vec![0x51, 0x20]
        .into_iter()
        .chain(tweaked_pubkey.clone())
        .collect();
    tx.add_input([0x22u8; 32], 1, 100_000_000, input_spk);

    let output_spk = vec![0x76, 0xa9, 0x14]
        .into_iter()
        .chain([0xBBu8; 20])
        .chain([0x88, 0xac])
        .collect();
    tx.add_output(99_800_000, output_spk);

    // Configure script-path spend (single leaf → empty merkle path)
    tx.set_scriptpath_spend(0, script_privkey, leaf, vec![], output_parity)?;

    let address = taproot_address(&tweaked_pubkey, "regtest")?;
    println!("   Taproot output address (with script): {}", address);

    let signed_tx = tx.sign()?;

    println!("   Script-path signed tx size: {} bytes", signed_tx.len());
    println!(
        "   Script-path tx hex (first 200 chars): {}\n",
        hex::encode(&signed_tx[..200.min(signed_tx.len())])
    );

    // ===================================================================
    // Summary
    // ===================================================================
    println!("Summary:");
    println!("  • Key-path: witness = [64-byte schnorr signature]");
    println!("  • Script-path: witness = [signature] [tapscript] [control block]");
    println!("  • Both spend the same output — different paths!");
    println!("  • Unified API → TaprootTransaction + set_keypath_spend / set_scriptpath_spend");

    Ok(())
}
