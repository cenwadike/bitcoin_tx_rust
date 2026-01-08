//! Comparison between Legacy and SegWit Transactions
//!
//! This example demonstrates the differences between legacy (P2PKH/P2SH)
//! and SegWit (P2WPKH/P2WSH) transactions.

use bitcoin_tx_rust::*;

fn main() {
    println!("=== Legacy vs SegWit Transaction Comparison ===\n");

    let (legacy_p2pkh_size, segwit_p2wpkh_size) = compare_p2pkh_vs_p2wpkh();
    let (legacy_p2sh_size, segwit_p2wsh_size) = compare_p2sh_vs_p2wsh();

    size_comparison(
        legacy_p2pkh_size,
        segwit_p2wpkh_size,
        legacy_p2sh_size,
        segwit_p2wsh_size,
    );
}

fn compare_p2pkh_vs_p2wpkh() -> (usize, usize) {
    println!("1. P2PKH (Legacy) vs P2WPKH (SegWit)");
    println!("====================================\n");

    let privkey = [0x11u8; 32];
    let pubkey = privkey_to_pubkey(&privkey).unwrap();

    // Legacy P2PKH
    println!("--- Legacy P2PKH ---");
    let mut legacy_tx = legacy::P2PKHTransaction::new();
    legacy_tx.add_input(TxInput::new([0x42u8; 32], 0));

    let output_spk = hex::decode("76a9143bc28d6d92d9073fb5e3adf481795eaf446bceed88ac").unwrap();
    legacy_tx.add_output(TxOutput::new(100_000_000, output_spk.clone()));

    let legacy_signed = legacy_tx.sign(&privkey, &pubkey, 0).unwrap();
    let legacy_p2pkh_size = legacy_signed.len();
    println!("Legacy P2PKH size: {} bytes", legacy_signed.len());
    println!(
        "Legacy P2PKH hex: {}...",
        &hex::encode(&legacy_signed)[0..40]
    );

    // SegWit P2WPKH
    println!("\n--- SegWit P2WPKH ---");
    let mut segwit_tx = P2WPKHTransaction::new();
    segwit_tx.add_input(TxInput::new([0x42u8; 32], 0));
    segwit_tx.add_output(TxOutput::new(100_000_000, output_spk));

    let segwit_signed = segwit_tx.sign(&privkey, &pubkey, 200_000_000).unwrap();
    let segwit_p2wpkh_size = segwit_signed.len();
    println!("SegWit P2WPKH size: {} bytes", segwit_signed.len());
    println!(
        "SegWit P2WPKH hex: {}...",
        &hex::encode(&segwit_signed)[0..40]
    );

    println!("\nKey Differences:");
    println!("  • Legacy has signature in scriptSig");
    println!("  • SegWit has signature in witness data");
    println!("  • SegWit includes marker (0x00) and flag (0x01) bytes");
    println!(
        "  • SegWit size: {} bytes ({:.1}% smaller)",
        segwit_signed.len(),
        100.0 * (1.0 - segwit_signed.len() as f64 / legacy_signed.len() as f64)
    );

    (legacy_p2pkh_size, segwit_p2wpkh_size)
}

fn compare_p2sh_vs_p2wsh() -> (usize, usize) {
    println!("\n\n2. P2SH (Legacy) vs P2WSH (SegWit) Multisig");
    println!("===========================================\n");

    let privkey1 = [0x11u8; 32];
    let privkey2 = [0x22u8; 32];
    let pubkey1 = privkey_to_pubkey(&privkey1).unwrap();
    let pubkey2 = privkey_to_pubkey(&privkey2).unwrap();

    // Legacy P2SH
    println!("--- Legacy P2SH 2-of-2 Multisig ---");
    let legacy_script =
        legacy::P2SHMultisigTransaction::create_2of2_redeem_script(&pubkey1, &pubkey2);
    let legacy_address = legacy::P2SHMultisigTransaction::script_to_p2sh(&legacy_script, "regtest");

    let mut legacy_multisig = legacy::P2SHMultisigTransaction::new(legacy_script);
    legacy_multisig.add_input(TxInput::new([0x42u8; 32], 0));
    legacy_multisig.add_output(TxOutput::new(
        100_000_000,
        vec![vec![0x76, 0xa9, 0x14], vec![0x00; 22]].concat(),
    ));

    let legacy_multisig_signed = legacy_multisig.sign(&[privkey1, privkey2], 0).unwrap();
    let legacy_p2sh_size = legacy_multisig_signed.len();

    println!("P2SH address: {}", legacy_address);
    println!("Legacy P2SH size: {} bytes", legacy_multisig_signed.len());

    // SegWit P2WSH
    println!("\n--- SegWit P2WSH 2-of-2 Multisig ---");
    let segwit_script = P2WSHMultisigTransaction::create_2of2_redeem_script(&pubkey1, &pubkey2);
    let segwit_address = script_to_p2wsh(&segwit_script, "regtest").unwrap();

    let mut segwit_multisig = P2WSHMultisigTransaction::new(segwit_script);
    segwit_multisig.add_input(TxInput::new([0x42u8; 32], 0));
    segwit_multisig.add_output(TxOutput::new(
        100_000_000,
        vec![vec![0x76, 0xa9, 0x14], vec![0x00; 22]].concat(),
    ));

    let segwit_multisig_signed = segwit_multisig
        .sign(&[privkey1, privkey2], 200_000_000)
        .unwrap();
    let segwit_p2wsh_size = segwit_multisig_signed.len();

    println!("P2WSH address: {}", segwit_address);
    println!("SegWit P2WSH size: {} bytes", segwit_multisig_signed.len());

    println!("\nKey Differences:");
    println!("  • P2SH address starts with '2' (regtest)");
    println!("  • P2WSH address starts with 'bcrt1' (regtest)");
    println!("  • P2SH uses 20-byte HASH160 of script");
    println!("  • P2WSH uses 32-byte SHA256 of script (better security)");
    println!(
        "  • SegWit size: {} bytes ({:.1}% smaller)",
        segwit_multisig_signed.len(),
        100.0 * (1.0 - segwit_multisig_signed.len() as f64 / legacy_multisig_signed.len() as f64)
    );

    (legacy_p2sh_size, segwit_p2wsh_size)
}

fn size_comparison(
    legacy_p2pkh_size: usize,
    segwit_p2wpkh_size: usize,
    legacy_p2sh_size: usize,
    segwit_p2wsh_size: usize,
) {
    println!("\n\n3. Transaction Size and Weight Comparison");
    println!("=========================================\n");

    println!("Block Weight Calculation (SegWit rules):");
    println!("  • Non-witness data: 4 weight units per byte");
    println!("  • Witness data:     1 weight unit per byte");
    println!("  • Block limit:      4,000,000 weight units (= 1,000,000 virtual bytes)\n");

    println!("Sizes from the examples above:");
    println!("┌────────────────────┬────────────┬──────────────────────────────┐");
    println!("│ Transaction Type   │ Raw Size   │ Notes                        │");
    println!("├────────────────────┼────────────┼──────────────────────────────┤");
    println!(
        "│ P2PKH (Legacy)     │ {:>6} B   │ All data counted at 4 WU/B   │",
        legacy_p2pkh_size
    );
    println!(
        "│ P2WPKH (SegWit)    │ {:>6} B   │ Witness discounted           │",
        segwit_p2wpkh_size
    );
    println!(
        "│ P2SH 2-of-2        │ {:>6} B   │ All data counted at 4 WU/B   │",
        legacy_p2sh_size
    );
    println!(
        "│ P2WSH 2-of-2       │ {:>6} B   │ Witness discounted           │",
        segwit_p2wsh_size
    );
    println!("└────────────────────┴────────────┴──────────────────────────────┘\n");

    // Approximate weight/vSize calculation (conservative for SegWit)
    let legacy_p2pkh_weight = legacy_p2pkh_size * 4;
    let legacy_p2pkh_vsize = legacy_p2pkh_size;

    // For SegWit: rough estimate - witness ~108 B for P2WPKH, ~217 B for P2WSH 2-of-2
    let p2wpkh_witness_est = 109; // sig (73) + pubkey (33) + overhead
    let p2wpkh_non_witness = segwit_p2wpkh_size - p2wpkh_witness_est - 2; // -2 for marker/flag
    let p2wpkh_weight = p2wpkh_non_witness * 4 + p2wpkh_witness_est;
    let p2wpkh_vsize = (p2wpkh_weight + 3) / 4; // ceil(weight/4)

    let p2wsh_witness_est = 217; // 1 (empty) + 2*73 sigs + 71 script + overhead
    let p2wsh_non_witness = segwit_p2wsh_size - p2wsh_witness_est - 2;
    let p2wsh_weight = p2wsh_non_witness * 4 + p2wsh_witness_est;
    let p2wsh_vsize = (p2wsh_weight + 3) / 4;

    let legacy_p2sh_weight = legacy_p2sh_size * 4;
    let legacy_p2sh_vsize = legacy_p2sh_size;

    println!("Estimated Weight and vSize (used for fees):");
    println!("┌────────────────────┬────────────┬────────────┐");
    println!("│ Transaction Type   │ vSize (vB) │ Weight (WU)│");
    println!("├────────────────────┼────────────┼────────────┤");
    println!(
        "│ P2PKH (Legacy)     │ {:>8}   │ {:>8}   │",
        legacy_p2pkh_vsize, legacy_p2pkh_weight
    );
    println!(
        "│ P2WPKH (SegWit)    │ {:>8}   │ {:>8}   │",
        p2wpkh_vsize, p2wpkh_weight
    );
    println!(
        "│ P2SH 2-of-2        │ {:>8}   │ {:>8}   │",
        legacy_p2sh_vsize, legacy_p2sh_weight
    );
    println!(
        "│ P2WSH 2-of-2       │ {:>8}   │ {:>8}   │",
        p2wsh_vsize, p2wsh_weight
    );
    println!("└────────────────────┴────────────┴────────────┘\n");

    println!("Example fee savings at 10 sat/vB:");
    let save_p2wpkh = (legacy_p2pkh_vsize - p2wpkh_vsize) * 10;
    let pct_p2wpkh =
        100.0 * (legacy_p2pkh_vsize as f64 - p2wpkh_vsize as f64) / legacy_p2pkh_vsize as f64;
    println!(
        "  • P2WPKH vs P2PKH: saves ~{} sats (~{:.0}% cheaper)",
        save_p2wpkh, pct_p2wpkh
    );

    let save_p2wsh = (legacy_p2sh_vsize - p2wsh_vsize) * 10;
    let pct_p2wsh =
        100.0 * (legacy_p2sh_vsize as f64 - p2wsh_vsize as f64) / legacy_p2sh_vsize as f64;
    println!(
        "  • P2WSH vs P2SH: saves ~{} sats (~{:.0}% cheaper)\n",
        save_p2wsh, pct_p2wsh
    );

    println!("✓ SegWit provides a witness discount:");
    println!("  Signature data costs 75% less in block space, leading to lower fees");
    println!("  and allowing more transactions per block.");
}
