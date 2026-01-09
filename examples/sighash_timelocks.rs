//! This file demonstrates:
//! 1. Different sighash algorithms (Legacy, SegWit v0, Taproot)
//! 2. Different sighash flags (ALL, NONE, SINGLE, ANYONECANPAY)
//! 3. Transaction-level timelocks (nLocktime, nSequence)
//! 4. Script-level timelocks (OP_CLTV, OP_CSV)

use bitcoin_tx_rust::*;

fn main() {
    println!("=== Bitcoin Sighash and Timelocks ===\n");

    signature_hash_evolution();
    sighash_flags();
    transaction_timelocks();
    script_timelocks();
}

/// Example 1: Signature Hash Algorithm Evolution
///
/// Demonstrates the three generations of sighash algorithms
fn signature_hash_evolution() {
    println!("--- Example 1: Signature Hash Algorithm Evolution ---");

    // Setup: Create a simple transaction
    let inputs = vec![SighashInput {
        txid: hex_to_array_32("dee5f46bf2b13839b927a83e3c19ec9e64488c0792a66f3f8716f3d2fba84acf"),
        vout: 0,
        script_pubkey: vec![
            0x76, 0xa9,
            0x14, // OP_DUP OP_HASH160 <20 bytes>
                 // ... pubkey hash would go here
        ],
        amount: 200_100_000, // 2.001 BTC
        sequence: 0xffffffff,
    }];

    let outputs = vec![
        SighashOutput {
            amount: 150_000_000, // 1.5 BTC
            script_pubkey: vec![0x00, 0x14 /* 20 bytes pubkey hash */],
        },
        SighashOutput {
            amount: 50_000_000, // 0.5 BTC
            script_pubkey: vec![0x00, 0x14 /* 20 bytes pubkey hash */],
        },
    ];

    // Legacy Sighash
    println!("\n1. Legacy Sighash (Pre-SegWit):");
    println!("   - Signs over entire transaction");
    println!("   - O(n²) complexity for n inputs");
    println!("   - Does NOT include input amounts");
    let legacy_sighash =
        LegacySighash::compute(2, &inputs, &outputs, 0, SighashFlag::All, 0).unwrap();
    println!("   Sighash: {}", hex::encode(legacy_sighash));

    // SegWit v0 Sighash
    println!("\n2. SegWit v0 Sighash (BIP-143):");
    println!("   - Uses intermediate hashes (O(n) complexity)");
    println!("   - INCLUDES input amount (protects cold wallets)");
    println!("   - Uses HASH256 (double SHA-256)");
    let segwit_sighash =
        SegwitV0Sighash::compute(2, &inputs, &outputs, 0, SighashFlag::All, 0).unwrap();
    println!("   Sighash: {}", hex::encode(segwit_sighash));

    // Taproot Sighash
    println!("\n3. Taproot Sighash (BIP-341):");
    println!("   - Signs over ALL input amounts (not just one)");
    println!("   - Signs over ALL scriptPubKeys");
    println!("   - Uses SHA256 (not double)");
    println!("   - Uses tagged hashes");
    println!("   - Includes input index being signed");
    let taproot_sighash =
        TaprootSighash::compute(2, &inputs, &outputs, 0, SighashFlag::Default, 0, false).unwrap();
    println!("   Sighash: {}", hex::encode(taproot_sighash));

    println!("\n✓ All three sighash generations computed successfully!\n");
}

/// Example 2: Sighash Flags - Jose's Restaurant Scenario
///
/// Demonstrates SIGHASH_NONE for partial transaction signing
fn sighash_flags() {
    println!("--- Example 2: Sighash Flags (Jose's Restaurant) ---");
    println!("\nScenario:");
    println!("  Jose wants to move funds from cold storage but doesn't know");
    println!("  the recipient yet. He uses SIGHASH_NONE to sign the input");
    println!("  without committing to outputs.\n");

    // Step 1: Jose signs with SIGHASH_NONE at home with cold wallet
    println!("Step 1: Sign cold wallet input with SIGHASH_NONE");

    let cold_input = SighashInput {
        txid: hex_to_array_32("6697e6a4cb3d06f4c8342583d8158a51513aedfa404514f4af740a222371431d"),
        vout: 0,
        script_pubkey: vec![0x51, 0x20], // Taproot
        amount: 200_100_000,             // 2.001 BTC
        sequence: 0xffffffff,
    };

    let hot_input = SighashInput {
        txid: hex_to_array_32("57bc2605d0218b4709f3eed074e998b51dd6998723a1024002f51df40c3f5044"),
        vout: 1,
        script_pubkey: vec![0x51, 0x20], // Taproot
        amount: 10_100_000,              // 0.101 BTC
        sequence: 0xffffffff,
    };

    let inputs = vec![cold_input.clone(), hot_input.clone()];

    // Sign with SIGHASH_NONE (no outputs committed)
    let cold_sighash = TaprootSighash::compute(
        2,
        &inputs,
        &[], // No outputs yet!
        0,   // First input (cold wallet)
        SighashFlag::None,
        0,
        false,
    )
    .unwrap();

    println!(
        "   Cold wallet signature (SIGHASH_NONE): {}",
        hex::encode(&cold_sighash[..8])
    );
    println!("   ✓ Can take this signature back to restaurant\n");

    // Step 2: Later, Jose adds outputs and signs hot wallet with SIGHASH_ALL
    println!("Step 2: Add outputs and sign hot wallet input with SIGHASH_ALL");

    let outputs = vec![
        SighashOutput {
            amount: 160_000_000, // 1.6 BTC to contractor
            script_pubkey: vec![0x00, 0x14],
        },
        SighashOutput {
            amount: 50_000_000, // 0.5 BTC change
            script_pubkey: vec![0x00, 0x14],
        },
    ];

    let hot_sighash = TaprootSighash::compute(
        2,
        &inputs,
        &outputs,
        1,                    // Second input (hot wallet)
        SighashFlag::Default, // SIGHASH_DEFAULT = implied ALL
        0,
        false,
    )
    .unwrap();

    println!(
        "   Hot wallet signature (SIGHASH_DEFAULT): {}",
        hex::encode(&hot_sighash[..8])
    );
    println!("   ✓ Transaction complete with both signatures!\n");

    // Demonstrate other sighash flags
    println!("Other Sighash Flags:");
    println!("  - SIGHASH_ALL: Signs all inputs and outputs (default)");
    println!("  - SIGHASH_NONE: Signs inputs but NO outputs");
    println!("  - SIGHASH_SINGLE: Signs inputs and ONE corresponding output");
    println!("  - ANYONECANPAY: Can be combined with above, signs only ONE input\n");

    println!("✓ Sighash flags demonstration complete!\n");
}

/// Example 3: Transaction-Level Timelocks
///
/// Demonstrates nLocktime and nSequence
fn transaction_timelocks() {
    println!("--- Example 3: Transaction-Level Timelocks ---");
    println!("\nScenario:");
    println!("  Kim gives her grandson Peter 0.1 BTC that he can only");
    println!("  spend after his 18th birthday (block 500).\n");

    // Create a transaction with absolute timelock (nLocktime)
    println!("1. Absolute Timelock (nLocktime):");
    let locktime = LockTime::BlockHeight(500);
    let mut tx = TimelockTransaction::new(locktime);

    // Add input with sequence that enables locktime
    tx.add_input(
        hex_to_array_32("f8830ec636a360ca9dc0f267ab7f29d2675a7066a9b405c1ae9e22664ffba557"),
        1,
        Sequence::enable_locktime(), // 0xfffffffe
    );

    // Add output
    tx.add_output(10_000_000, vec![0x00, 0x14]); // 0.1 BTC

    println!(
        "   Version: {} (v2 required for relative timelocks)",
        tx.version
    );
    println!("   nLocktime: {} (block height)", locktime.to_u32());
    println!(
        "   nSequence: 0x{:08x} (enables locktime)",
        tx.inputs[0].sequence.to_u32()
    );

    // Check if transaction is final
    println!("\n   At block 499: final = {}", tx.is_final(499, 0));
    println!("   At block 500: final = {}", tx.is_final(500, 0));

    // Demonstrate relative timelock (nSequence)
    println!("\n2. Relative Timelock (nSequence):");
    println!("   Instead of absolute block 500, wait 398 blocks after confirmation\n");

    let mut tx2 = TimelockTransaction::new(LockTime::None);

    // Use relative timelock in sequence
    let relative_seq = Sequence::from_blocks(398);
    tx2.add_input(
        hex_to_array_32("f8830ec636a360ca9dc0f267ab7f29d2675a7066a9b405c1ae9e22664ffba557"),
        1,
        relative_seq,
    );
    tx2.add_output(10_000_000, vec![0x00, 0x14]);

    println!("   nLocktime: 0 (not used)");
    println!("   nSequence: 0x{:08x}", relative_seq.to_u32());
    println!(
        "   Relative locktime: {} blocks",
        relative_seq.locktime_value()
    );
    println!(
        "   Enabled: {}",
        relative_seq.is_relative_locktime_enabled()
    );

    // Time-based relative timelock
    let time_seq = Sequence::from_time_intervals(72); // 72 * 512 seconds ≈ 10 hours
    println!("\n   Time-based relative locktime:");
    println!("   nSequence: 0x{:08x}", time_seq.to_u32());
    println!(
        "   Intervals: {} (× 512 seconds)",
        time_seq.locktime_value()
    );
    println!("   Is time-based: {}", time_seq.is_time_based());

    println!("\n✓ Transaction-level timelocks demonstration complete!\n");
}

/// Example 4: Script-Level Timelocks
///
/// Demonstrates OP_CHECKLOCKTIMEVERIFY and OP_CHECKSEQUENCEVERIFY
fn script_timelocks() {
    println!("--- Example 4: Script-Level Timelocks ---");
    println!("\nScript-level timelocks enforce locktime constraints in the scriptPubKey");
    println!("itself, providing stronger guarantees than transaction-level timelocks.\n");

    // Example pubkey
    let pubkey = vec![
        0x02, 0x46, 0x6d, 0x7f, 0xca, 0xe5, 0x63, 0xe5, 0xcb, 0x09, 0xa0, 0xd1, 0x87, 0x0b, 0xb5,
        0x80, 0x34, 0x48, 0x04, 0x61, 0x78, 0x79, 0xa1, 0x49, 0x49, 0xcf, 0x22, 0x28, 0x5f, 0x1b,
        0xae, 0x3f, 0x27,
    ];

    // 1. OP_CHECKLOCKTIMEVERIFY
    println!("1. OP_CHECKLOCKTIMEVERIFY (OP_CLTV):");
    let locktime = LockTime::BlockHeight(500);
    let cltv_script = OpCheckLockTimeVerify::build_script(locktime, &pubkey);

    println!("   Script: <500> OP_CLTV OP_DROP <pubkey> OP_CHECKSIG");
    println!("   Hex: {}", hex::encode(&cltv_script));
    println!("   Length: {} bytes", cltv_script.len());

    // Verify constraints
    let tx_locktime = LockTime::BlockHeight(500);
    let tx_sequence = Sequence::enable_locktime();
    let valid = OpCheckLockTimeVerify::verify(locktime, tx_locktime, tx_sequence);
    println!("\n   Spending transaction must have:");
    println!("   - nLocktime >= 500");
    println!("   - nSequence != 0xffffffff");
    println!("   Valid: {}", valid);

    // 2. OP_CHECKSEQUENCEVERIFY
    println!("\n2. OP_CHECKSEQUENCEVERIFY (OP_CSV):");
    let sequence = Sequence::from_blocks(398);
    let csv_script = OpCheckSequenceVerify::build_script(sequence, &pubkey);

    println!("   Script: <398> OP_CSV OP_DROP <pubkey> OP_CHECKSIG");
    println!("   Hex: {}", hex::encode(&csv_script));
    println!("   Length: {} bytes", csv_script.len());

    // Verify constraints
    let tx_sequence = Sequence::from_blocks(398);
    let valid = OpCheckSequenceVerify::verify(sequence, tx_sequence);
    println!("\n   Spending transaction must have:");
    println!("   - nSequence >= 398 (relative locktime)");
    println!("   - Version >= 2");
    println!("   Valid: {}", valid);

    // Comparison
    println!("\n3. Comparison:");
    println!("   OP_CLTV:");
    println!("   ✓ Enforces absolute timelock at script level");
    println!("   ✓ Prevents Kim from spending before block 500");
    println!("   ✓ Kim cannot create a different transaction without the timelock\n");

    println!("   OP_CSV:");
    println!("   ✓ Enforces relative timelock at script level");
    println!("   ✓ Locktime starts when UTXO is confirmed");
    println!("   ✓ Useful for Lightning HTLCs and payment channels");

    println!("\n✓ Script-level timelocks demonstration complete!\n");
}

// Helper function to convert hex string to 32-byte array
fn hex_to_array_32(hex: &str) -> [u8; 32] {
    let bytes = hex::decode(hex).expect("Invalid hex");
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    array
}
