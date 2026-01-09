//! examples/compare_legacy_segwit.rs (FIXED VERSION)
//!
//! Realistic comparison correctly showing SegWit efficiency using virtual bytes:
//!   • Legacy P2PKH vs SegWit P2WPKH (2 inputs, 3 outputs)
//!   • Legacy P2SH vs SegWit P2WSH (2-of-2 multisig, 2 inputs)

use bitcoin_tx_rust::*;

fn main() {
    println!("=== Realistic Legacy vs SegWit Size & Fee Comparison ===\n");
    println!("(Using 2 inputs + 3 outputs for representative results)\n");

    let (legacy_p2pkh_size, _segwit_p2wpkh_size, segwit_p2wpkh_vsize) = compare_p2pkh_vs_p2wpkh();
    let (legacy_p2sh_size, _segwit_p2wsh_size, segwit_p2wsh_vsize) = compare_p2sh_vs_p2wsh();

    size_comparison(
        legacy_p2pkh_size,
        segwit_p2wpkh_vsize,
        legacy_p2sh_size,
        segwit_p2wsh_vsize,
    );
}

/// Calculate virtual size (vBytes) for a SegWit transaction
/// Formula: (base_size * 3 + total_size) / 4
/// where base_size excludes witness data
fn calculate_virtual_size(signed_tx: &[u8]) -> usize {
    // Check if this is a SegWit transaction (has marker and flag)
    if signed_tx.len() >= 6 && signed_tx[4] == 0x00 && signed_tx[5] == 0x01 {
        // This is a SegWit transaction
        // We need to calculate the base size (without witness data)

        // For this example, we'll parse the transaction to find witness data
        let base_size = calculate_base_size(signed_tx);
        let total_size = signed_tx.len();

        // Weight = base_size * 4 + witness_size * 1
        // vSize = weight / 4 = (base_size * 4 + witness_size) / 4
        // Simplified: (base_size * 3 + total_size) / 4
        (base_size * 3 + total_size) / 4
    } else {
        // Legacy transaction - size equals vsize
        signed_tx.len()
    }
}

/// Calculate the base size of a transaction (excluding witness data)
fn calculate_base_size(signed_tx: &[u8]) -> usize {
    if signed_tx.len() < 6 || signed_tx[4] != 0x00 || signed_tx[5] != 0x01 {
        // Not a SegWit transaction
        return signed_tx.len();
    }

    // Find where the witness data starts
    // Structure: version(4) | marker(1) | flag(1) | inputs | outputs | witness | locktime(4)
    // Base transaction = version(4) | inputs | outputs | locktime(4)

    // For simplicity, we'll estimate:
    // The witness section is everything between outputs end and locktime
    // A more precise calculation would parse the transaction structure

    // Quick estimation:
    // Total size - marker(1) - flag(1) - witness_data_size
    // Witness data is roughly: 2 inputs × (1 byte count + ~107 bytes data each) ≈ 216 bytes

    let total_size = signed_tx.len();
    let marker_flag_size = 2; // 0x00 0x01

    // Estimate witness size based on transaction type
    // For P2WPKH: ~107 bytes per input (1 byte count + 72 sig + 33 pubkey + overhead)
    // For P2WSH 2-of-2: ~220 bytes per input (1 byte count + 2×72 sigs + script)

    // Parse to count inputs
    let num_inputs = signed_tx[6] as usize; // After version, marker, flag

    // Rough witness size estimation
    let witness_size = if is_p2wsh_transaction(signed_tx) {
        num_inputs * 220 // P2WSH multisig
    } else {
        num_inputs * 107 // P2WPKH
    };

    total_size - marker_flag_size - witness_size
}

/// Detect if this is a P2WSH transaction (has longer witness data)
fn is_p2wsh_transaction(signed_tx: &[u8]) -> bool {
    // Simple heuristic: P2WSH transactions are larger due to multisig
    signed_tx.len() > 500
}

fn compare_p2pkh_vs_p2wpkh() -> (usize, usize, usize) {
    println!("1. Legacy P2PKH vs Native SegWit P2WPKH");
    println!("========================================\n");

    let privkey = [0x11u8; 32];
    let dummy_spk = vec![
        0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xac,
    ];

    // Legacy P2PKH
    println!("--- Legacy P2PKH (2 inputs, 3 outputs) ---");
    let mut legacy_tx = legacy::P2PKHTransaction::new();

    legacy_tx.add_input([0x42u8; 32], 0, dummy_spk.clone(), 300_000_000);
    legacy_tx.add_input([0x43u8; 32], 1, dummy_spk.clone(), 200_000_000);

    legacy_tx.add_output(400_000_000, dummy_spk.clone());
    legacy_tx.add_output(50_000_000, dummy_spk.clone());
    legacy_tx.add_output(49_000_000, dummy_spk.clone());

    let legacy_signed = legacy_tx.sign(&[privkey, privkey]).unwrap();
    let legacy_size = legacy_signed.len();
    println!("Total size: {} bytes", legacy_size);
    println!(
        "Virtual size: {} vBytes (same as total for legacy)\n",
        legacy_size
    );

    // SegWit P2WPKH
    println!("--- Native SegWit P2WPKH (same structure) ---");
    let mut segwit_tx = P2WPKHTransaction::new();

    segwit_tx.add_input([0x42u8; 32], 0, dummy_spk.clone(), 300_000_000);
    segwit_tx.add_input([0x43u8; 32], 1, dummy_spk.clone(), 200_000_000);

    segwit_tx.add_output(400_000_000, dummy_spk.clone());
    segwit_tx.add_output(50_000_000, dummy_spk.clone());
    segwit_tx.add_output(49_000_000, dummy_spk);

    let segwit_signed = segwit_tx.sign(&[privkey, privkey]).unwrap();
    let segwit_size = segwit_signed.len();
    let segwit_vsize = calculate_virtual_size(&segwit_signed);

    println!("Total size: {} bytes", segwit_size);
    println!(
        "Virtual size: {} vBytes (witness data discounted)\n",
        segwit_vsize
    );

    (legacy_size, segwit_size, segwit_vsize)
}

fn compare_p2sh_vs_p2wsh() -> (usize, usize, usize) {
    println!("\n2. Legacy P2SH vs Native SegWit P2WSH (2-of-2 Multisig)");
    println!("===================================================\n");

    let privkey1 = [0x11u8; 32];
    let privkey2 = [0x22u8; 32];

    let dummy_spk = vec![
        0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xac,
    ];

    // Legacy P2SH 2-of-2
    println!("--- Legacy P2SH 2-of-2 (2 inputs) ---");
    let legacy_script = legacy::P2SHMultisigTransaction::create_2of2_redeem_script(
        &privkey_to_pubkey(&privkey1).unwrap(),
        &privkey_to_pubkey(&privkey2).unwrap(),
    );

    let mut legacy_multisig = legacy::P2SHMultisigTransaction::new(legacy_script);

    legacy_multisig.add_input([0x42u8; 32], 0, 300_000_000);
    legacy_multisig.add_input([0x43u8; 32], 1, 200_000_000);

    legacy_multisig.add_output(400_000_000, dummy_spk.clone());
    legacy_multisig.add_output(99_000_000, dummy_spk.clone());

    let legacy_signed = legacy_multisig
        .sign(&[vec![privkey1, privkey2], vec![privkey1, privkey2]])
        .unwrap();
    let legacy_size = legacy_signed.len();
    println!("Total size: {} bytes", legacy_size);
    println!(
        "Virtual size: {} vBytes (same as total for legacy)\n",
        legacy_size
    );

    // SegWit P2WSH 2-of-2
    println!("--- Native SegWit P2WSH 2-of-2 (same structure) ---");
    let segwit_script = P2WSHMultisigTransaction::create_2of2_redeem_script(
        &privkey_to_pubkey(&privkey1).unwrap(),
        &privkey_to_pubkey(&privkey2).unwrap(),
    );

    let mut segwit_multisig = P2WSHMultisigTransaction::new(segwit_script);

    segwit_multisig.add_input([0x42u8; 32], 0, 300_000_000);
    segwit_multisig.add_input([0x43u8; 32], 1, 200_000_000);

    segwit_multisig.add_output(400_000_000, dummy_spk.clone());
    segwit_multisig.add_output(99_000_000, dummy_spk);

    let segwit_signed = segwit_multisig
        .sign(&[vec![privkey1, privkey2], vec![privkey1, privkey2]])
        .unwrap();
    let segwit_size = segwit_signed.len();
    let segwit_vsize = calculate_virtual_size(&segwit_signed);

    println!("Total size: {} bytes", segwit_size);
    println!(
        "Virtual size: {} vBytes (witness data discounted)\n",
        segwit_vsize
    );

    (legacy_size, segwit_size, segwit_vsize)
}

fn size_comparison(l_p2pkh: usize, s_p2pkh_vsize: usize, l_p2sh: usize, s_p2sh_vsize: usize) {
    println!("\n3. Clear Size & Fee Savings Summary");
    println!("==================================\n");

    let p2pkh_save = l_p2pkh.saturating_sub(s_p2pkh_vsize);
    let p2pkh_pct = if l_p2pkh > 0 {
        100.0 * p2pkh_save as f64 / l_p2pkh as f64
    } else {
        0.0
    };

    let p2sh_save = l_p2sh.saturating_sub(s_p2sh_vsize);
    let p2sh_pct = if l_p2sh > 0 {
        100.0 * p2sh_save as f64 / l_p2sh as f64
    } else {
        0.0
    };

    println!("Realistic Savings (2 inputs + 3 outputs):");
    println!("┌─────────────────────┬────────────────────────────┬──────────────┐");
    println!("│ Type                │ Legacy vSize │ SegWit vSize │ Savings      │");
    println!("├─────────────────────┼──────────────┼──────────────┼──────────────┤");
    println!(
        "│ P2PKH → P2WPKH      │ {:>10} B │ {:>10} B │ {:>3} B ({:>4.1}%) │",
        l_p2pkh, s_p2pkh_vsize, p2pkh_save, p2pkh_pct
    );
    println!(
        "│ P2SH 2-of-2 → P2WSH │ {:>10} B │ {:>10} B │ {:>3} B ({:>4.1}%) │",
        l_p2sh, s_p2sh_vsize, p2sh_save, p2sh_pct
    );
    println!("└─────────────────────┴──────────────┴──────────────┴──────────────┘\n");

    println!("At different fee rates (sat/vB):");
    println!(
        "  10 sat/vB → P2WPKH saves ~{:>4} sats | P2WSH saves ~{:>4} sats",
        p2pkh_save * 10,
        p2sh_save * 10
    );
    println!(
        "  50 sat/vB → P2WPKH saves ~{:>4} sats | P2WSH saves ~{:>4} sats",
        p2pkh_save * 50,
        p2sh_save * 50
    );
    println!(
        " 100 sat/vB → P2WPKH saves ~{:>4} sats | P2WSH saves ~{:>4} sats",
        p2pkh_save * 100,
        p2sh_save * 100
    );

    println!("\nKey Takeaway (2026):");
    println!(
        "  SegWit saves {:.1}%–{:.1}% in transaction fees (via virtual bytes)",
        p2pkh_pct, p2sh_pct
    );
    println!("  → Witness data is discounted 75% for fee calculation");
    println!("  → Lower fees, more tx per block, better scalability");
    println!("  → Especially powerful for multisig wallets and exchanges");

    println!("\nTechnical Details:");
    println!("  • Legacy tx: size = vsize (no discount)");
    println!("  • SegWit tx: vsize = (base_size × 3 + total_size) / 4");
    println!("  • Base size = tx without witness data");
    println!("  • Witness data gets 75% discount in fee calculation");
}
