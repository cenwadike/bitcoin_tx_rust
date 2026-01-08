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
//! ```rust,no_run
//! use bitcoin_tx_rust::*;
//!
//! // Generate keys
//! let privkey = generate_privkey();
//! let pubkey = privkey_to_pubkey(&privkey).unwrap();
//!
//! // Create P2WPKH address
//! let address = pk_to_p2wpkh(&pubkey, "regtest").unwrap();
//!
//! // Create transaction
//! let mut tx = P2WPKHTransaction::new();
//! tx.add_input(TxInput::new([0u8; 32], 0));
//! tx.add_output(TxOutput::new(100_000_000, [vec![0x00, 0x14], vec![0x00; 20]].concat()));
//!
//! // Sign transaction
//! let signed = tx.sign(&privkey, &pubkey, 200_000_000).unwrap();
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

pub mod legacy;
pub mod segwit;
pub mod utils;

pub use legacy::*;
pub use segwit::*;
pub use utils::*;

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_complete_p2wpkh_workflow() {
        // Generate sender keys
        let sender_privkey = [0x11u8; 32];
        let sender_pubkey = privkey_to_pubkey(&sender_privkey).unwrap();

        // Create sender's P2WPKH address
        let sender_address = pk_to_p2wpkh(&sender_pubkey, "regtest").unwrap();
        println!("Sender address: {}", sender_address);

        // Create receiver's scriptPubKey
        let receiver_address = "bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw";
        let receiver_spk = bech32_to_spk("bcrt", receiver_address).unwrap();

        // Create change output
        let change_privkey = [0x22u8; 32];
        let change_pubkey = privkey_to_pubkey(&change_privkey).unwrap();
        let change_pk_hash = hash160(&change_pubkey);
        let mut change_spk = vec![0x00, 0x14];
        change_spk.extend_from_slice(&change_pk_hash);

        // Build transaction
        let mut tx = P2WPKHTransaction::new();

        // Add input (simulated UTXO)
        let input = TxInput::new([0x42u8; 32], 0);
        tx.add_input(input);

        // Add outputs
        let output1 = TxOutput::new(150_000_000, receiver_spk); // 1.5 BTC
        let output2 = TxOutput::new(50_000_000, change_spk); // 0.5 BTC
        tx.add_output(output1);
        tx.add_output(output2);

        // Sign transaction
        let input_value = 200_100_000; // 2.001 BTC
        let signed_tx = tx
            .sign(&sender_privkey, &sender_pubkey, input_value)
            .unwrap();

        println!("Signed transaction hex: {}", hex::encode(&signed_tx));
        assert!(!signed_tx.is_empty());
        assert!(signed_tx.len() > 100);
    }

    #[test]
    fn test_multiple_inputs_workflow() {
        // Andreas's keys
        let privkey_a = [0x11u8; 32];
        let pubkey_a = privkey_to_pubkey(&privkey_a).unwrap();

        // Lisa's keys
        let privkey_l = [0x22u8; 32];
        let pubkey_l = privkey_to_pubkey(&privkey_l).unwrap();

        // Create transaction with multiple inputs
        let mut tx = MultiInputP2WPKHTransaction::new();

        // Add Andreas's input
        tx.add_input(TxInput::new([0x44u8; 32], 0));

        // Add Lisa's input
        tx.add_input(TxInput::new([0x55u8; 32], 0));

        // Add charity outputs
        let charity1_spk =
            bech32_to_spk("bcrt", "bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw").unwrap();
        let charity2_spk =
            bech32_to_spk("bcrt", "bcrt1q6mlqttg852e63uahyglwla55xusryqp08vx9w2").unwrap();
        let charity3_spk =
            bech32_to_spk("bcrt", "bcrt1qe9y40n9uwzh34mzj02w3xx9zkhgke6wxcql4lk").unwrap();

        tx.add_output(TxOutput::new(20_000_000, charity1_spk)); // 0.2 BTC
        tx.add_output(TxOutput::new(20_000_000, charity2_spk)); // 0.2 BTC
        tx.add_output(TxOutput::new(20_000_000, charity3_spk)); // 0.2 BTC

        // Add Lisa's change output
        let lisa_change_spk =
            bech32_to_spk("bcrt", "bcrt1qqde3c4pmvrr9d3pav3v6hlpp9l3sm6rxnj8dcm").unwrap();
        tx.add_output(TxOutput::new(10_000_000, lisa_change_spk)); // 0.1 BTC

        // Sign with both keys
        let input_data = vec![
            (privkey_a.to_vec(), pubkey_a, 30_000_000), // Andreas: 0.3 BTC
            (privkey_l.to_vec(), pubkey_l, 40_100_000), // Lisa: 0.401 BTC
        ];

        let signed_tx = tx.sign(&input_data).unwrap();
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

        // Add input
        tx.add_input(TxInput::new([0x98u8; 32], 0));

        // Add outputs (P2PKH for simplicity in this example)
        let receiver_spk =
            hex::decode("76a9143bc28d6d92d9073fb5e3adf481795eaf446bceed88ac").unwrap();
        let change_privkey = [0x44u8; 32];
        let change_pubkey = privkey_to_pubkey(&change_privkey).unwrap();
        let change_pk_hash = hash160(&change_pubkey);
        let mut change_spk = vec![0x76, 0xa9, 0x14];
        change_spk.extend_from_slice(&change_pk_hash);
        change_spk.extend_from_slice(&[0x88, 0xac]);

        tx.add_output(TxOutput::new(150_000_000, receiver_spk));
        tx.add_output(TxOutput::new(50_000_000, change_spk));

        // Sign with both private keys
        let signed_tx = tx.sign(&[privkey1, privkey2], 200_100_000).unwrap();
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
        tx.add_input(TxInput::new([0xAAu8; 32], 0));

        let output_spk = [vec![0x00, 0x14], vec![0x00; 20]].concat(); // Dummy P2WPKH
        tx.add_output(TxOutput::new(100_000_000, output_spk));

        // Sign with first 3 keys
        let signing_keys = [privkeys[0], privkeys[1], privkeys[2]];
        let signed_tx = tx.sign(&signing_keys, 100_100_000).unwrap();

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

        // Create 2-of-3 multisig
        let redeem_script = legacy::P2SHMultisigTransaction::create_2of3_redeem_script(
            &pubkey1, &pubkey2, &pubkey3,
        );

        println!("P2SH redeem script: {}", hex::encode(&redeem_script));

        // Get P2SH address
        let address = legacy::P2SHMultisigTransaction::script_to_p2sh(&redeem_script, "regtest");
        println!("P2SH address: {}", address);

        // Create and sign transaction
        let mut tx = legacy::P2SHMultisigTransaction::new(redeem_script);
        tx.add_input(TxInput::new([0x70u8; 32], 0));

        let output_spk = hex::decode("76a9143bc28d6d92d9073fb5e3adf481795eaf446bceed88ac").unwrap();
        tx.add_output(TxOutput::new(150_000_000, output_spk));

        let change_spk = hex::decode("76a914cc1b07838e387deacd0e5232e1e8b49f4c29e48488ac").unwrap();
        tx.add_output(TxOutput::new(50_000_000, change_spk));

        // Sign with 2 keys (2-of-3)
        let signed_tx = tx.sign(&[privkey1, privkey2], 0).unwrap();
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
}
