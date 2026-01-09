//! PSBT (Partially Signed Bitcoin Transaction) Examples
//!
//! Demonstrates various PSBT workflows including:
//! - Creating PSBTs
//! - Adding signatures from multiple parties
//! - Combining PSBTs
//! - Finalizing and extracting transactions
//! - Hardware wallet workflows
//! - Multisig coordination

// use bitcoin_tx_rust::prelude::*;
use bitcoin_tx_rust::{
    AbsoluteTimelockSupport, LockTime, P2WPKHTransaction, P2WSHMultisigTransaction,
    RelativeTimelockSupport, Sequence, psbt::*,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== PSBT (Partially Signed Bitcoin Transaction) Examples ===\n");

    // Example 1: Basic PSBT workflow
    println!("1. Basic PSBT Workflow");
    demo_basic_psbt()?;

    // Example 2: Multisig PSBT
    println!("\n2. Multisig PSBT (2-of-3)");
    demo_multisig_psbt()?;

    // Example 3: Hardware wallet workflow
    println!("\n3. Hardware Wallet Workflow");
    demo_hardware_wallet()?;

    // Example 4: Combining PSBTs
    println!("\n4. Combining PSBTs from Multiple Signers");
    demo_combine_psbts()?;

    // Example 5: Air-gapped signing
    println!("\n5. Air-Gapped Signing Workflow");
    demo_air_gapped_signing()?;

    // Example 6: PSBT with timelocks
    println!("\n6. PSBT with Timelocks");
    demo_psbt_with_timelocks()?;

    Ok(())
}

/// Example 1: Basic PSBT workflow
fn demo_basic_psbt() -> Result<(), Box<dyn std::error::Error>> {
    println!("  Creating unsigned transaction...");

    // Create unsigned transaction
    let mut tx = P2WPKHTransaction::new();
    tx.add_input([0x42; 32], 0, vec![0x00, 0x14], 100_000_000);
    tx.add_output(99_000_000, vec![0x00, 0x14]);

    let unsigned_tx = tx.build_unsigned();

    // Create PSBT
    let mut psbt = Psbt::new(unsigned_tx)?;
    println!("  ✓ PSBT created");

    // Add witness UTXO info
    psbt.set_witness_utxo(
        0,
        100_000_000,
        vec![
            0x00, 0x14, 0x75, 0xa1, 0x04, 0x8e, 0x4d, 0x39, 0x15, 0x9f, 0x59, 0xe1, 0xd2, 0x38,
            0x11, 0x9c, 0xd4, 0xba, 0x1b, 0x63, 0x1e, 0x98,
        ],
    )?;
    println!("  ✓ Witness UTXO added");

    // Add BIP-32 derivation path
    let pubkey = vec![0x02; 33]; // Example pubkey
    psbt.add_input_bip32_derivation(
        0,
        pubkey,
        [0x12, 0x34, 0x56, 0x78], // Master fingerprint
        vec![0x80000000 + 84, 0x80000000 + 0, 0x80000000 + 0, 0, 0], // m/84'/0'/0'/0/0
    )?;
    println!("  ✓ BIP-32 derivation path added");

    // Serialize to base64
    let base64 = psbt.to_base64();
    println!("  ✓ PSBT serialized to base64");
    println!("    Length: {} bytes", base64.len());

    // Deserialize from base64
    let decoded = Psbt::from_base64(&base64)?;
    println!("  ✓ PSBT deserialized successfully");

    // Add partial signature (in real scenario, this would be done by signer)
    let signature = vec![0x30; 71]; // Dummy signature
    let signer_pubkey = vec![0x02; 33];
    decoded
        .clone()
        .add_partial_sig(0, signer_pubkey, signature)?;
    println!("  ✓ Partial signature added");

    Ok(())
}

/// Example 2: Multisig 2-of-3 PSBT
fn demo_multisig_psbt() -> Result<(), Box<dyn std::error::Error>> {
    println!("  Setting up 2-of-3 multisig...");

    // Create multisig redeem script
    let pubkey1 = vec![0x02; 33];
    let pubkey2 = vec![0x03; 33];
    let pubkey3 = vec![0x04; 33];

    let witness_script = P2WSHMultisigTransaction::create_multisig_redeem_script(
        2,
        &[pubkey1.clone(), pubkey2.clone(), pubkey3.clone()],
    )?;

    // Create transaction
    let mut tx = P2WSHMultisigTransaction::new(witness_script.clone());
    tx.add_input([0x42; 32], 0, 100_000_000);
    tx.add_output(99_000_000, vec![0x00, 0x20]);

    let unsigned_tx = tx.build_unsigned();

    // Create PSBT
    let mut psbt = Psbt::new(unsigned_tx)?;
    println!("  ✓ PSBT created for 2-of-3 multisig");

    // Add witness UTXO
    psbt.set_witness_utxo(0, 100_000_000, vec![0x00, 0x20])?;

    // Add witness script
    psbt.set_input_witness_script(0, witness_script)?;
    println!("  ✓ Witness script added");

    // Add BIP-32 paths for all three keys
    psbt.add_input_bip32_derivation(0, pubkey1, [0x12, 0x34, 0x56, 0x78], vec![0, 0])?;
    psbt.add_input_bip32_derivation(0, pubkey2, [0x12, 0x34, 0x56, 0x78], vec![0, 1])?;
    psbt.add_input_bip32_derivation(0, pubkey3, [0x12, 0x34, 0x56, 0x78], vec![0, 2])?;
    println!("  ✓ BIP-32 derivation paths added for all keys");

    // Signer 1 adds their signature
    psbt.add_partial_sig(0, vec![0x02; 33], vec![0x30; 71])?;
    println!("  ✓ Signer 1 signed");

    // Signer 2 adds their signature
    psbt.add_partial_sig(0, vec![0x03; 33], vec![0x30; 71])?;
    println!("  ✓ Signer 2 signed");

    // Now we have 2-of-3 signatures - can finalize
    psbt.finalize_input(0)?;
    println!("  ✓ Input finalized (2-of-3 threshold met)");

    Ok(())
}

/// Example 3: Hardware wallet workflow
fn demo_hardware_wallet() -> Result<(), Box<dyn std::error::Error>> {
    println!("  Simulating hardware wallet workflow...");

    // Step 1: Software wallet creates PSBT
    println!("\n  [Software Wallet]");
    let mut tx = P2WPKHTransaction::new();
    tx.add_input([0x42; 32], 0, vec![0x00, 0x14], 100_000_000);
    tx.add_output(50_000_000, vec![0x00, 0x14]); // Send 0.5 BTC
    tx.add_output(49_900_000, vec![0x00, 0x14]); // Change

    let unsigned_tx = tx.build_unsigned();
    let mut psbt = Psbt::new(unsigned_tx)?;

    psbt.set_witness_utxo(0, 100_000_000, vec![0x00, 0x14])?;
    psbt.add_input_bip32_derivation(
        0,
        vec![0x02; 33],
        [0xaa, 0xbb, 0xcc, 0xdd],
        vec![0x80000000 + 84, 0x80000000 + 0, 0x80000000 + 0, 0, 5],
    )?;

    let psbt_base64 = psbt.to_base64();
    println!("    ✓ Created PSBT");
    println!("    ✓ Encoded as base64 for hardware wallet");

    // Step 2: Transfer to hardware wallet (via USB/QR code)
    println!("\n  [Hardware Wallet]");
    println!("    ⚡ Received PSBT via USB/QR");

    let mut hw_psbt = Psbt::from_base64(&psbt_base64)?;

    // Hardware wallet verifies and displays transaction details
    println!("    🔍 Verifying transaction details:");
    println!("       - Output 1: 0.5 BTC");
    println!("       - Output 2: 0.499 BTC (change)");
    println!("       - Fee: 0.001 BTC");

    // User approves on hardware wallet
    println!("    ✅ User approved on device");

    // Hardware wallet signs
    hw_psbt.add_partial_sig(0, vec![0x02; 33], vec![0x30; 71])?;
    println!("    ✓ Signed with hardware key");

    let signed_base64 = hw_psbt.to_base64();

    // Step 3: Transfer back to software wallet
    println!("\n  [Software Wallet]");
    println!("    ⚡ Received signed PSBT");

    let _final_psbt = Psbt::from_base64(&signed_base64)?;
    println!("    ✓ Signature verified");
    println!("    ✓ Ready to broadcast");

    Ok(())
}

/// Example 4: Combining PSBTs from multiple signers
fn demo_combine_psbts() -> Result<(), Box<dyn std::error::Error>> {
    println!("  Creating base PSBT...");

    // Create base transaction
    let witness_script = vec![0x52, 0x21, 0x00, 0x21, 0x01, 0x52, 0xae]; // 2-of-2
    let mut tx = P2WSHMultisigTransaction::new(witness_script.clone());
    tx.add_input([0x42; 32], 0, 100_000_000);
    tx.add_output(99_000_000, vec![0x00, 0x20]);

    let unsigned_tx = tx.build_unsigned();

    // Signer 1 creates and signs PSBT
    println!("\n  [Signer 1]");
    let mut psbt1 = Psbt::new(unsigned_tx.clone())?;
    psbt1.set_witness_utxo(0, 100_000_000, vec![0x00, 0x20])?;
    psbt1.set_input_witness_script(0, witness_script.clone())?;
    psbt1.add_partial_sig(0, vec![0x02; 33], vec![0x30; 71])?;
    println!("    ✓ Signed by Signer 1");

    // Signer 2 creates and signs PSBT
    println!("\n  [Signer 2]");
    let mut psbt2 = Psbt::new(unsigned_tx)?;
    psbt2.set_witness_utxo(0, 100_000_000, vec![0x00, 0x20])?;
    psbt2.set_input_witness_script(0, witness_script)?;
    psbt2.add_partial_sig(0, vec![0x03; 33], vec![0x30; 71])?;
    println!("    ✓ Signed by Signer 2");

    // Coordinator combines PSBTs
    println!("\n  [Coordinator]");
    psbt1.combine(&psbt2)?;
    println!("    ✓ Combined PSBTs");
    println!(
        "    ✓ Now has {} signatures",
        psbt1.inputs[0].partial_sigs.len()
    );

    // Finalize
    psbt1.finalize_input(0)?;
    println!("    ✓ Transaction finalized");

    Ok(())
}

/// Example 5: Air-gapped signing workflow
fn demo_air_gapped_signing() -> Result<(), Box<dyn std::error::Error>> {
    println!("  Simulating air-gapped signing...");

    // Step 1: Online computer creates PSBT
    println!("\n  [Online Computer]");
    let mut tx = P2WPKHTransaction::new();
    tx.add_input([0x42; 32], 0, vec![0x00, 0x14], 100_000_000);
    tx.add_output(99_000_000, vec![0x00, 0x14]);

    let unsigned_tx = tx.build_unsigned();
    let mut psbt = Psbt::new(unsigned_tx)?;
    psbt.set_witness_utxo(0, 100_000_000, vec![0x00, 0x14])?;

    let base64 = psbt.to_base64();
    println!("    ✓ Created PSBT");
    println!("    ✓ Encoded to base64");

    // Step 2: Transfer via QR code / USB drive
    println!("\n  [Transfer]");
    println!("    📱 Showing QR code...");
    println!("    💾 Or saving to USB drive...");

    // Step 3: Air-gapped computer signs
    println!("\n  [Air-Gapped Computer]");
    println!("    📷 Scanned QR code");
    println!("    💾 Or loaded from USB");

    let mut offline_psbt = Psbt::from_base64(&base64)?;
    println!("    ✓ PSBT loaded");

    // Air-gapped computer has the private key
    println!("    🔐 Signing with offline key...");
    offline_psbt.add_partial_sig(0, vec![0x02; 33], vec![0x30; 71])?;
    println!("    ✓ Signed");

    let signed_base64 = offline_psbt.to_base64();
    println!("    📱 Showing signed PSBT as QR code");

    // Step 4: Transfer back
    println!("\n  [Online Computer]");
    println!("    📷 Scanned signed QR code");

    let _final_psbt = Psbt::from_base64(&signed_base64)?;
    println!("    ✓ Received signed PSBT");
    println!("    ✓ Broadcasting transaction...");

    Ok(())
}

/// Example 6: PSBT with timelocks
fn demo_psbt_with_timelocks() -> Result<(), Box<dyn std::error::Error>> {
    println!("  Creating PSBT with timelocks...");

    let mut tx = P2WPKHTransaction::new();
    tx.set_locktime(LockTime::BlockHeight(800000));

    tx.add_input([0x42; 32], 0, vec![0x00, 0x14], 100_000_000);
    tx.set_sequence(0, Sequence::from_blocks(144))?; // ~1 day relative lock

    tx.add_output(99_000_000, vec![0x00, 0x14]);

    let unsigned_tx = tx.build_unsigned();

    // Create PSBT
    let mut psbt = Psbt::new(unsigned_tx)?;
    println!("  ✓ PSBT created with timelocks");

    psbt.set_witness_utxo(0, 100_000_000, vec![0x00, 0x14])?;

    // Set custom sighash type (ALL with relative locktime)
    psbt.inputs[0].sighash_type = Some(0x01);
    println!("  ✓ Absolute locktime: block 800000");
    println!("  ✓ Relative locktime: 144 blocks (~1 day)");

    // Sign
    psbt.add_partial_sig(0, vec![0x02; 33], vec![0x30; 71])?;
    println!("  ✓ Signed");

    // Finalize
    psbt.finalize_input(0)?;
    println!("  ✓ Finalized");
    println!("  ℹ Transaction can only be broadcast after:");
    println!("    - Block height 800000");
    println!("    - 144 blocks after input confirmation");

    Ok(())
}

/// Helper: Display PSBT information
#[allow(dead_code)]
fn display_psbt_info(psbt: &Psbt) {
    println!("\n  PSBT Information:");
    println!("    Version: {:?}", psbt.global.version);
    println!("    Inputs: {}", psbt.inputs.len());
    println!("    Outputs: {}", psbt.outputs.len());

    for (i, input) in psbt.inputs.iter().enumerate() {
        println!("\n    Input {}:", i);
        println!("      Witness UTXO: {}", input.witness_utxo.is_some());
        println!(
            "      Non-Witness UTXO: {}",
            input.non_witness_utxo.is_some()
        );
        println!("      Partial Sigs: {}", input.partial_sigs.len());
        println!("      Redeem Script: {}", input.redeem_script.is_some());
        println!("      Witness Script: {}", input.witness_script.is_some());
        println!("      BIP32 Derivations: {}", input.bip32_derivation.len());
        println!(
            "      Finalized: {}",
            input.final_script_sig.is_some() || input.final_script_witness.is_some()
        );
    }
}
