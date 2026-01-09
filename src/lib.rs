//! # Bitcoin Transaction Library
//!
//! A comprehensive educational library for creating and signing Bitcoin transactions.
//!
//! ## Features
//!
//! - **SegWit Transactions**
//!   - P2WPKH (Pay-to-Witness-Public-Key-Hash) single and multiple inputs
//!   - P2WSH (Pay-to-Witness-Script-Hash) multisig (2-of-2, M-of-N)
//!
//! - **Legacy Transactions**
//!   - P2PKH (Pay-to-Public-Key-Hash)
//!   - P2SH (Pay-to-Script-Hash) multisig
//!
//! - **Utilities**
//!   - Cryptographic functions (SHA256, HASH160, HASH256)
//!   - Key generation and management
//!   - Address encoding (Bech32, Base58)
//!   - BIP143 signing for SegWit
//!
//! ## Usage
//!
//! ```rust
//! use bitcoin_tx_rust::*;
//!
//! // Generate keys
//! let privkey = generate_privkey();
//! let pubkey = privkey_to_pubkey(&privkey).unwrap();
//!
//! // Create P2WPKH address (for reference)
//! let address = pk_to_p2wpkh(&pubkey, "regtest").unwrap();
//!
//! // 1. Create the transaction
//! let mut tx = P2WPKHTransaction::new();
//!
//! // 2. Add input (correct constructor + full arguments)
//! tx.add_input(
//!     [0u8; 32],                // txid
//!     0,                        // vout
//!     vec![0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // script_pubkey (dummy P2WPKH)
//!     200_000_000               // amount in satoshis
//! );
//!
//! // 3. Add output (correct constructor)
//! tx.add_output(
//!     100_000_000,              // amount
//!     [vec![0x00, 0x14], vec![0x00; 20]].concat()  // dummy P2WPKH script_pubkey
//! );
//!
//! // 4. Sign the transaction
//! // Note: input index 0, amount must match what was added above
//! let signed = tx.sign(&[privkey]).unwrap();
//!
//! println!("Signed transaction: {}", hex::encode(&signed));
//! ```
//! ## Examples
//!
//! See the `examples/` directory for complete working examples:
//!
//! - `all_transactions.rs` - Comprehensive examples of all transaction types
//! - `bitcoin_core_test.rs` - Integration with Bitcoin Core
//! - `legacy_p2sh.rs` - Legacy P2SH multisig transactions
//! - `compare_legacy_segwit.rs` - Comparison between legacy and SegWit
//!
//! ## Safety
//!
//! ⚠️ **Educational Purpose Only**: This library is designed for learning and testing.
//! Do not use in production without thorough security review and testing.
//!
//! ## Testing with Bitcoin Core
//!
//! ```bash
//! # Start Bitcoin Core in regtest mode
//! bitcoind -regtest -daemon
//!
//! # Run examples
//! cargo run --example all_transactions
//! cargo run --example bitcoin_core_test
//! ```

pub mod flags;
pub mod legacy;
pub mod psbt;
pub mod segwit;
pub mod taproot;
pub mod timelocks;
pub mod traits;
pub mod utils;

pub use flags::*;
pub use legacy::*;
pub use psbt::*;
pub use segwit::*;
pub use taproot::*;
pub use timelocks::*;
pub use traits::*;
pub use utils::*;

#[cfg(test)]
mod integration_tests {
    use crate::address::taproot_address;

    use super::*;

    #[test]
    fn test_complete_p2wpkh_workflow() {
        let sender_privkey = [0x11u8; 32];

        let receiver_spk =
            bech32_to_spk("bcrt", "bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw").unwrap();

        let change_pk_hash = hash160(&privkey_to_pubkey(&[0x22u8; 32]).unwrap());
        let mut change_spk = vec![0x00, 0x14];
        change_spk.extend_from_slice(&change_pk_hash);

        let mut tx = P2WPKHTransaction::new();

        // Fixed: use correct add_input arguments
        tx.add_input(
            [0x42u8; 32], // txid
            0,            // vout
            vec![
                0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ], // script_pubkey
            200_100_000,  // amount
        );

        tx.add_output(150_000_000, receiver_spk);
        tx.add_output(50_000_000, change_spk);

        // Fixed: sign takes &[ [u8;32] ] — array of privkeys
        let signed_tx = tx.sign(&[sender_privkey]).unwrap();

        assert!(!signed_tx.is_empty());
    }

    #[test]
    fn test_multiple_inputs_workflow() {
        // Andreas's keys
        let privkey_a = [0x11u8; 32];
        let _pubkey_a = privkey_to_pubkey(&privkey_a).unwrap();

        // Lisa's keys
        let privkey_l = [0x22u8; 32];
        let _pubkey_l = privkey_to_pubkey(&privkey_l).unwrap();

        // Create transaction with multiple inputs
        let mut tx = MultiInputP2WPKHTransaction::new();

        // Add Andreas's input (correct arguments: txid, vout, script_pubkey, amount)
        tx.add_input(
            [0x44u8; 32], // txid
            0,            // vout
            vec![
                0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ], // dummy P2WPKH script_pubkey
            30_000_000,   // amount (0.3 BTC)
        );

        // Add Lisa's input
        tx.add_input(
            [0x55u8; 32],
            0,
            vec![
                0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
            40_100_000, // 0.401 BTC
        );

        // Add charity outputs (correct: amount, script_pubkey)
        let charity1_spk =
            bech32_to_spk("bcrt", "bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw").unwrap();
        let charity2_spk =
            bech32_to_spk("bcrt", "bcrt1q6mlqttg852e63uahyglwla55xusryqp08vx9w2").unwrap();
        let charity3_spk =
            bech32_to_spk("bcrt", "bcrt1qe9y40n9uwzh34mzj02w3xx9zkhgke6wxcql4lk").unwrap();

        tx.add_output(20_000_000, charity1_spk);
        tx.add_output(20_000_000, charity2_spk);
        tx.add_output(20_000_000, charity3_spk);

        // Add Lisa's change output
        let lisa_change_spk =
            bech32_to_spk("bcrt", "bcrt1qqde3c4pmvrr9d3pav3v6hlpp9l3sm6rxnj8dcm").unwrap();
        tx.add_output(10_000_000, lisa_change_spk);

        // Sign with both private keys (pass as slice of [u8;32])
        let privkeys = [privkey_a, privkey_l];

        let signed_tx = tx.sign(&privkeys).unwrap();

        println!(
            "Multi-input signed transaction hex: {}",
            hex::encode(&signed_tx)
        );
        assert!(!signed_tx.is_empty());
    }

    #[test]
    fn test_p2wsh_multisig_workflow() {
        // Create two keys for 2-of-2 multisig
        let privkey1 = [0x11u8; 32];
        let privkey2 = [0x22u8; 32];

        let pubkey1 = privkey_to_pubkey(&privkey1).unwrap();
        let pubkey2 = privkey_to_pubkey(&privkey2).unwrap();

        // Create 2-of-2 multisig redeem script
        let redeem_script = P2WSHMultisigTransaction::create_2of2_redeem_script(&pubkey1, &pubkey2);
        println!("Redeem script: {}", hex::encode(&redeem_script));

        // Create P2WSH address
        let p2wsh_address = script_to_p2wsh(&redeem_script, "regtest").unwrap();
        println!("P2WSH address: {}", p2wsh_address);

        // Create transaction
        let mut tx = P2WSHMultisigTransaction::new(redeem_script);

        // Add input (correct arguments: txid, vout, amount)
        tx.add_input(
            [0x98u8; 32], // txid
            0,            // vout
            200_100_000,  // amount in satoshis
        );

        // Add outputs (correct: amount, script_pubkey)
        let receiver_spk =
            hex::decode("76a9143bc28d6d92d9073fb5e3adf481795eaf446bceed88ac").unwrap();

        let change_privkey = [0x44u8; 32];
        let change_pubkey = privkey_to_pubkey(&change_privkey).unwrap();
        let change_pk_hash = hash160(&change_pubkey);
        let mut change_spk = vec![0x76, 0xa9, 0x14];
        change_spk.extend_from_slice(&change_pk_hash);
        change_spk.extend_from_slice(&[0x88, 0xac]);

        tx.add_output(150_000_000, receiver_spk);
        tx.add_output(50_000_000, change_spk);

        // Sign with both private keys
        // Note: sign expects &[Vec<[u8; 32]>] — one Vec per input
        // For single input → pass vec![vec![privkey1, privkey2]]
        let signing_keys_per_input = vec![
            vec![privkey1, privkey2], // All keys needed for this input (2-of-2)
        ];

        let signed_tx = tx.sign(&signing_keys_per_input).unwrap();

        println!("P2WSH signed transaction hex: {}", hex::encode(&signed_tx));
        assert!(!signed_tx.is_empty());
    }

    #[test]
    fn test_3of5_multisig() {
        // Create 5 keypairs
        let privkeys: Vec<[u8; 32]> = (0..5)
            .map(|i| {
                let mut key = [0u8; 32];
                key[0] = (i + 1) as u8;
                key
            })
            .collect();

        let pubkeys: Vec<Vec<u8>> = privkeys
            .iter()
            .map(|pk| privkey_to_pubkey(pk).unwrap())
            .collect();

        // Create 3-of-5 multisig script
        let redeem_script =
            P2WSHMultisigTransaction::create_multisig_redeem_script(3, &pubkeys).unwrap();

        // Create P2WSH address
        let address = script_to_p2wsh(&redeem_script, "regtest").unwrap();
        println!("3-of-5 P2WSH address: {}", address);

        // Create transaction
        let mut tx = P2WSHMultisigTransaction::new(redeem_script);

        // Add input (correct: txid, vout, amount)
        tx.add_input(
            [0xAAu8; 32], // txid
            0,            // vout
            100_100_000,  // amount in satoshis
        );

        // Add output (correct: amount, script_pubkey)
        let output_spk = [vec![0x00, 0x14], vec![0x00; 20]].concat(); // Dummy P2WPKH
        tx.add_output(100_000_000, output_spk);

        // Sign with first 3 keys
        // IMPORTANT: sign expects &[Vec<[u8;32]>] — one Vec per input
        // For single input with 3-of-5 → pass vec![vec![key1, key2, key3]]
        let signing_keys_per_input = vec![
            vec![privkeys[0], privkeys[1], privkeys[2]], // 3 keys for this input
        ];

        let signed_tx = tx.sign(&signing_keys_per_input).unwrap();

        assert!(!signed_tx.is_empty());
        println!("3-of-5 multisig signed successfully");
    }

    #[test]
    fn test_legacy_p2sh_multisig() {
        // Test legacy P2SH transaction
        let privkey1 = [0x11u8; 32];
        let privkey2 = [0x22u8; 32];
        let privkey3 = [0x33u8; 32];

        let pubkey1 = privkey_to_pubkey(&privkey1).unwrap();
        let pubkey2 = privkey_to_pubkey(&privkey2).unwrap();
        let pubkey3 = privkey_to_pubkey(&privkey3).unwrap();

        // Create 2-of-3 multisig redeem script
        let redeem_script = legacy::P2SHMultisigTransaction::create_2of3_redeem_script(
            &pubkey1, &pubkey2, &pubkey3,
        );

        println!("P2SH redeem script: {}", hex::encode(&redeem_script));

        // Get P2SH address
        let address = legacy::P2SHMultisigTransaction::script_to_p2sh(&redeem_script, "regtest");
        println!("P2SH address: {}", address);

        // Create and sign transaction
        let mut tx = legacy::P2SHMultisigTransaction::new(redeem_script);

        // Add input (correct: txid, vout, amount)
        tx.add_input(
            [0x70u8; 32], // txid
            0,            // vout
            200_000_000,  // amount in satoshis
        );

        // Add outputs (correct: amount, script_pubkey)
        let output_spk = hex::decode("76a9143bc28d6d92d9073fb5e3adf481795eaf446bceed88ac").unwrap();
        tx.add_output(150_000_000, output_spk);

        let change_spk = hex::decode("76a914cc1b07838e387deacd0e5232e1e8b49f4c29e48488ac").unwrap();
        tx.add_output(50_000_000, change_spk);

        // Sign with 2 keys (2-of-3)
        // Note: sign expects &[Vec<[u8;32]>] — one Vec per input
        // For single input → vec![vec![key1, key2]]
        let signing_keys_per_input = vec![
            vec![privkey1, privkey2], // 2 keys for this input
        ];

        let signed_tx = tx.sign(&signing_keys_per_input).unwrap();

        println!("P2SH signed transaction: {}", hex::encode(&signed_tx));
        assert!(!signed_tx.is_empty());
    }

    #[test]
    fn test_address_generation_consistency() {
        // Test that addresses are generated consistently
        let privkey = [0x11u8; 32];
        let pubkey = privkey_to_pubkey(&privkey).unwrap();

        let addr1 = pk_to_p2wpkh(&pubkey, "regtest").unwrap();
        let addr2 = pk_to_p2wpkh(&pubkey, "regtest").unwrap();

        assert_eq!(addr1, addr2);
        assert_eq!(addr1, "bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw");
    }

    #[test]
    fn test_p2tr_key_path_workflow() {
        let internal_privkey = [0xB0u8; 32];
        let _internal_pubkey = schnorr_pubkey_gen(&internal_privkey).unwrap();

        // Create modern unified Taproot transaction
        let mut tx = TaprootTransaction::new();

        // Add input (dummy P2TR script_pubkey = 0x51 0x20 + 32-byte key)
        let dummy_input_spk = vec![0x51, 0x20].into_iter().chain([0xAAu8; 32]).collect();
        tx.add_input([0x11u8; 32], 0, 100_000_000, dummy_input_spk);

        // Add output (P2TR or whatever you want)
        let output_spk = vec![0x51, 0x20].into_iter().chain([0xAAu8; 32]).collect();
        tx.add_output(99_900_000, output_spk);

        // Configure key-path spend (no merkle root = pure key-path)
        tx.set_keypath_spend(0, internal_privkey, None).unwrap();

        // Get tweaked pubkey (you can expose this or compute manually)
        // For simplicity, we'll use a dummy tweaked key here — in real code compute it
        let tweaked_pubkey = vec![0xAAu8; 32]; // placeholder — replace with real computation

        let address = taproot_address(&tweaked_pubkey, "regtest").unwrap();
        println!("P2TR key-path address: {}", address);

        // Sign
        let signed_tx = tx.sign().unwrap();

        println!("P2TR key-path signed tx: {}", hex::encode(&signed_tx));
        assert!(!signed_tx.is_empty());
        assert!(signed_tx.len() > 150);
    }

    #[test]
    fn test_p2tr_script_path_workflow_single_leaf() {
        let internal_privkey = [0xA0u8; 32];
        let internal_pubkey = schnorr_pubkey_gen(&internal_privkey).unwrap();

        let script_privkey = [0xF0u8; 32];
        let script_pubkey = schnorr_pubkey_gen(&script_privkey).unwrap();

        let tapscript = create_p2pk_tapscript(&script_pubkey);
        let leaf = TapLeaf::new(tapscript);

        let leaf_hash = leaf.leaf_hash();

        let (output_parity, tweaked_pubkey) =
            taproot_tweak_pubkey(&internal_pubkey, Some(&leaf_hash)).unwrap();

        // Modern unified tx
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

        // Configure script-path spend (single leaf → empty merkle_path)
        tx.set_scriptpath_spend(0, script_privkey, leaf, vec![], output_parity)
            .unwrap();

        let signed_tx = tx.sign().unwrap();

        println!(
            "P2TR script-path single-leaf signed tx: {}",
            hex::encode(&signed_tx)
        );
        println!("Size: {} bytes", signed_tx.len());

        let address = taproot_address(&tweaked_pubkey, "regtest").unwrap();
        println!("P2TR script-path address: {}", address);

        assert!(!signed_tx.is_empty());
        assert!(signed_tx.len() > 200);
        assert!(signed_tx.len() < 300);
    }

    #[test]
    fn test_p2tr_script_path_workflow_multi_leaf() {
        let internal_privkey = [0xA0u8; 32];
        let internal_pubkey = schnorr_pubkey_gen(&internal_privkey).unwrap();

        let privkey_a = [0xF0u8; 32];
        let privkey_b = [0xF1u8; 32];
        let privkey_c = [0xF2u8; 32];

        let pubkey_a = schnorr_pubkey_gen(&privkey_a).unwrap();
        let pubkey_b = schnorr_pubkey_gen(&privkey_b).unwrap();
        let pubkey_c = schnorr_pubkey_gen(&privkey_c).unwrap();

        let script_a = create_p2pk_tapscript(&pubkey_a);
        let script_b = create_p2pk_tapscript(&pubkey_b);
        let script_c = create_p2pk_tapscript(&pubkey_c);

        let leaf_a = TapLeaf::new(script_a);
        let leaf_b = TapLeaf::new(script_b.clone());
        let leaf_c = TapLeaf::new(script_c);

        let tree = create_3leaf_taptree(leaf_a.clone(), leaf_b.clone(), leaf_c.clone());
        let merkle_root = tree.merkle_root();

        let hash_a = leaf_a.leaf_hash();
        let hash_c = leaf_c.leaf_hash();
        let merkle_path_for_b = vec![hash_a, hash_c];

        let (output_parity, tweaked_pubkey) =
            taproot_tweak_pubkey(&internal_pubkey, Some(&merkle_root)).unwrap();

        // Modern tx
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

        // Configure script-path spend using leaf B
        tx.set_scriptpath_spend(0, privkey_b, leaf_b, merkle_path_for_b, output_parity)
            .unwrap();

        let signed_tx = tx.sign().unwrap();

        println!(
            "P2TR multi-leaf script-path signed tx: {}",
            hex::encode(&signed_tx)
        );
        println!("Size: {} bytes", signed_tx.len());

        let address = taproot_address(&tweaked_pubkey, "regtest").unwrap();
        println!("P2TR multi-leaf script-path address: {}", address);

        assert!(!signed_tx.is_empty());
        assert!(signed_tx.len() > 250);
        assert!(signed_tx.len() < 350);
    }

    #[test]
    fn test_complete_transaction_flow() {
        println!("\n=== Complete Transaction Flow ===\n");

        // 1. Create transaction with timelock
        println!("1. Create transaction with absolute timelock");
        let mut tx = TimelockTransaction::new(LockTime::BlockHeight(500));

        // 2. Add inputs with proper sequence
        tx.add_input([0x42; 32], 0, Sequence::enable_locktime());
        println!("   ✓ Added input with locktime-enabled sequence");

        // 3. Add outputs
        tx.add_output(100_000_000, vec![0x00, 0x14]);
        println!("   ✓ Added output");

        // 4. Serialize
        let serialized = tx.serialize();
        assert!(!serialized.is_empty());
        println!("   ✓ Serialized: {} bytes", serialized.len());

        // 5. Check finality at different heights
        assert!(!tx.is_final(499, 0));
        assert!(tx.is_final(500, 0));
        println!("   ✓ Finality checks passed");

        println!("\n✅ Complete flow successful!\n");
    }

    #[test]
    fn test_sighash_consistency() {
        println!("\n=== Sighash Consistency Test ===\n");

        let inputs = vec![SighashInput {
            txid: [0x42; 32],
            vout: 0,
            script_pubkey: vec![0x00, 0x14],
            amount: 100_000_000,
            sequence: 0xffffffff,
        }];

        let outputs = vec![SighashOutput {
            amount: 99_000_000,
            script_pubkey: vec![0x00, 0x14],
        }];

        // Compute with same parameters twice
        let hash1 = SegwitV0Sighash::compute(2, &inputs, &outputs, 0, SighashFlag::All, 0).unwrap();

        let hash2 = SegwitV0Sighash::compute(2, &inputs, &outputs, 0, SighashFlag::All, 0).unwrap();

        assert_eq!(hash1, hash2);
        println!("   ✓ Same inputs produce same sighash");

        // Change amount should change sighash
        let mut inputs_diff = inputs.clone();
        inputs_diff[0].amount = 200_000_000;

        let hash3 =
            SegwitV0Sighash::compute(2, &inputs_diff, &outputs, 0, SighashFlag::All, 0).unwrap();

        assert_ne!(hash1, hash3);
        println!("   ✓ Different amount produces different sighash");

        println!("\n✅ Consistency test passed!\n");
    }
}
