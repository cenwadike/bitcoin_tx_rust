//! Legacy P2SH (Pay-to-Script-Hash) Multisig Transaction Implementation
//!
//! This implements P2SH multisig transactions as they were used before SegWit.
//! For new implementations, consider using P2WSH (SegWit version) instead.

use crate::segwit::p2wpkh_single_input::{TxInput, TxOutput};
use crate::utils::*;
use num_integer::Integer;

/// Legacy P2SH Multisig Transaction Builder
pub struct P2SHMultisigTransaction {
    version: u32,
    inputs: Vec<TxInput>,
    outputs: Vec<TxOutput>,
    locktime: u32,
    redeem_script: Vec<u8>,
}

impl P2SHMultisigTransaction {
    pub fn new(redeem_script: Vec<u8>) -> Self {
        Self {
            version: 2,
            inputs: Vec::new(),
            outputs: Vec::new(),
            locktime: 0,
            redeem_script,
        }
    }

    /// Create a 2-of-2 multisig redeem script
    pub fn create_2of2_redeem_script(pubkey1: &[u8], pubkey2: &[u8]) -> Vec<u8> {
        let mut script = Vec::new();

        // OP_2
        script.push(0x52);

        // Push first pubkey
        script.push(pubkey1.len() as u8);
        script.extend_from_slice(pubkey1);

        // Push second pubkey
        script.push(pubkey2.len() as u8);
        script.extend_from_slice(pubkey2);

        // OP_2
        script.push(0x52);

        // OP_CHECKMULTISIG
        script.push(0xae);

        script
    }

    /// Create a 2-of-3 multisig redeem script
    pub fn create_2of3_redeem_script(pubkey1: &[u8], pubkey2: &[u8], pubkey3: &[u8]) -> Vec<u8> {
        let mut script = Vec::new();

        // OP_2 (requires 2 signatures)
        script.push(0x52);

        // Push all three pubkeys
        script.push(pubkey1.len() as u8);
        script.extend_from_slice(pubkey1);

        script.push(pubkey2.len() as u8);
        script.extend_from_slice(pubkey2);

        script.push(pubkey3.len() as u8);
        script.extend_from_slice(pubkey3);

        // OP_3 (total of 3 pubkeys)
        script.push(0x53);

        // OP_CHECKMULTISIG
        script.push(0xae);

        script
    }

    /// Create a general m-of-n multisig redeem script
    pub fn create_multisig_redeem_script(m: u8, pubkeys: &[Vec<u8>]) -> Result<Vec<u8>, String> {
        if m == 0 || m > pubkeys.len() as u8 {
            return Err("Invalid m value for multisig".to_string());
        }

        if pubkeys.len() > 20 {
            return Err("Too many pubkeys for multisig (max 20)".to_string());
        }

        let mut script = Vec::new();

        // OP_m (0x50 + m for 1-16)
        script.push(0x50 + m);

        // Push all pubkeys
        for pubkey in pubkeys {
            script.push(pubkey.len() as u8);
            script.extend_from_slice(pubkey);
        }

        // OP_n
        script.push(0x50 + pubkeys.len() as u8);

        // OP_CHECKMULTISIG
        script.push(0xae);

        Ok(script)
    }

    /// Convert redeem script to P2SH address
    pub fn script_to_p2sh(script: &[u8], network: &str) -> String {
        let script_hash = hash160(script);

        let prefix = match network {
            "mainnet" => 0x05u8,
            "testnet" | "regtest" => 0xc4u8,
            _ => 0xc4u8,
        };

        // Build address bytes: prefix + hash + checksum
        let mut addr_bytes = vec![prefix];
        addr_bytes.extend_from_slice(&script_hash);

        // Calculate checksum (first 4 bytes of double SHA256)
        let checksum = &hash256(&addr_bytes)[0..4];
        addr_bytes.extend_from_slice(checksum);

        // Encode as base58
        base58_encode(&addr_bytes)
    }

    pub fn add_input(&mut self, input: TxInput) {
        self.inputs.push(input);
    }

    pub fn add_output(&mut self, output: TxOutput) {
        self.outputs.push(output);
    }

    pub fn get_redeem_script(&self) -> &[u8] {
        &self.redeem_script
    }

    /// Build unsigned transaction
    pub fn build_unsigned(&self) -> Vec<u8> {
        let mut tx = Vec::new();

        // Version
        tx.extend_from_slice(&self.version.to_le_bytes());

        // Input count
        tx.extend_from_slice(&varint_len(&vec![0u8; self.inputs.len()]));

        // Inputs
        for input in &self.inputs {
            tx.extend_from_slice(&input.serialize());
        }

        // Output count
        tx.extend_from_slice(&varint_len(&vec![0u8; self.outputs.len()]));

        // Outputs
        for output in &self.outputs {
            tx.extend_from_slice(&output.serialize());
        }

        // Locktime
        tx.extend_from_slice(&self.locktime.to_le_bytes());

        tx
    }

    /// Sign the P2SH multisig transaction
    ///
    /// For a 2-of-2 multisig, provide 2 private keys
    /// For a 2-of-3 multisig, provide any 2 private keys
    pub fn sign(
        &self,
        privkeys: &[[u8; 32]],
        input_index: usize,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if input_index >= self.inputs.len() {
            return Err("Input index out of bounds".into());
        }

        let sighash_type = 1u32; // SIGHASH_ALL

        // Build transaction with redeemScript in place of scriptSig
        let mut tx_to_sign = Vec::new();

        // Version
        tx_to_sign.extend_from_slice(&self.version.to_le_bytes());

        // Input count
        tx_to_sign.extend_from_slice(&varint_len(&vec![0u8; self.inputs.len()]));

        // Inputs
        for (i, input) in self.inputs.iter().enumerate() {
            let mut txid_le = input.txid;
            txid_le.reverse();
            tx_to_sign.extend_from_slice(&txid_le);
            tx_to_sign.extend_from_slice(&input.vout.to_le_bytes());

            if i == input_index {
                // For the input being signed, use the redeemScript
                tx_to_sign.extend_from_slice(&varint_len(&self.redeem_script));
                tx_to_sign.extend_from_slice(&self.redeem_script);
            } else {
                // For other inputs, use empty scriptSig
                tx_to_sign.push(0x00);
            }

            tx_to_sign.extend_from_slice(&input.sequence.to_le_bytes());
        }

        // Outputs
        tx_to_sign.extend_from_slice(&varint_len(&vec![0u8; self.outputs.len()]));
        for output in &self.outputs {
            tx_to_sign.extend_from_slice(&output.serialize());
        }

        // Locktime
        tx_to_sign.extend_from_slice(&self.locktime.to_le_bytes());

        // Sighash flag
        tx_to_sign.extend_from_slice(&sighash_type.to_le_bytes());

        // Hash the transaction
        let sighash = hash256(&tx_to_sign);

        // Create signatures
        let mut signatures = Vec::new();
        for privkey in privkeys {
            let mut signature = sign_hash(privkey, &sighash)?;
            signature.push(0x01); // Append SIGHASH_ALL
            signatures.push(signature);
        }

        // Build scriptSig: OP_0 <sig1> <sig2> ... <redeemScript>
        let mut script_sig = Vec::new();

        // OP_0 for CHECKMULTISIG bug
        script_sig.push(0x00);

        // Add all signatures
        for sig in &signatures {
            script_sig.extend_from_slice(&pushbytes(sig));
        }

        // Add redeem script
        script_sig.extend_from_slice(&pushbytes(&self.redeem_script));

        // Build final signed transaction
        let mut signed_tx = Vec::new();

        // Version
        signed_tx.extend_from_slice(&self.version.to_le_bytes());

        // Input count
        signed_tx.extend_from_slice(&varint_len(&vec![0u8; self.inputs.len()]));

        // Inputs
        for (i, input) in self.inputs.iter().enumerate() {
            let mut txid_le = input.txid;
            txid_le.reverse();
            signed_tx.extend_from_slice(&txid_le);
            signed_tx.extend_from_slice(&input.vout.to_le_bytes());

            if i == input_index {
                // Add the scriptSig with signatures
                signed_tx.extend_from_slice(&varint_len(&script_sig));
                signed_tx.extend_from_slice(&script_sig);
            } else {
                // Empty scriptSig for other inputs
                signed_tx.push(0x00);
            }

            signed_tx.extend_from_slice(&input.sequence.to_le_bytes());
        }

        // Outputs
        signed_tx.extend_from_slice(&varint_len(&vec![0u8; self.outputs.len()]));
        for output in &self.outputs {
            signed_tx.extend_from_slice(&output.serialize());
        }

        // Locktime
        signed_tx.extend_from_slice(&self.locktime.to_le_bytes());

        Ok(signed_tx)
    }
}

/// Base58 encoding helper
fn base58_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    // Convert to big integer
    let mut num = num_bigint::BigUint::from_bytes_be(data);
    let base = num_bigint::BigUint::from(58u32);
    let zero = num_bigint::BigUint::from(0u32);

    let mut result = Vec::new();

    while num > zero {
        let (quotient, remainder) = num.div_rem(&base);
        result.push(ALPHABET[remainder.to_u32_digits()[0] as usize]);
        num = quotient;
    }

    // Add leading '1's for leading zero bytes
    for &byte in data {
        if byte == 0 {
            result.push(ALPHABET[0]);
        } else {
            break;
        }
    }

    result.reverse();
    String::from_utf8(result).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_2of2_redeem_script() {
        let privkey1 = [0x11u8; 32];
        let privkey2 = [0x22u8; 32];

        let pubkey1 = privkey_to_pubkey(&privkey1).unwrap();
        let pubkey2 = privkey_to_pubkey(&privkey2).unwrap();

        let script = P2SHMultisigTransaction::create_2of2_redeem_script(&pubkey1, &pubkey2);

        // Verify script structure
        assert_eq!(script[0], 0x52); // OP_2
        assert_eq!(script[script.len() - 2], 0x52); // OP_2
        assert_eq!(script[script.len() - 1], 0xae); // OP_CHECKMULTISIG
    }

    #[test]
    fn test_2of3_redeem_script() {
        let privkey1 = [0x11u8; 32];
        let privkey2 = [0x22u8; 32];
        let privkey3 = [0x33u8; 32];

        let pubkey1 = privkey_to_pubkey(&privkey1).unwrap();
        let pubkey2 = privkey_to_pubkey(&privkey2).unwrap();
        let pubkey3 = privkey_to_pubkey(&privkey3).unwrap();

        let script =
            P2SHMultisigTransaction::create_2of3_redeem_script(&pubkey1, &pubkey2, &pubkey3);

        // Verify script structure
        assert_eq!(script[0], 0x52); // OP_2 (requires 2 sigs)
        assert_eq!(script[script.len() - 2], 0x53); // OP_3 (3 pubkeys)
        assert_eq!(script[script.len() - 1], 0xae); // OP_CHECKMULTISIG
    }

    #[test]
    fn test_p2sh_address_generation() {
        let privkey1 = [0x11u8; 32];
        let privkey2 = [0x22u8; 32];

        let pubkey1 = privkey_to_pubkey(&privkey1).unwrap();
        let pubkey2 = privkey_to_pubkey(&privkey2).unwrap();

        let script = P2SHMultisigTransaction::create_2of2_redeem_script(&pubkey1, &pubkey2);
        let address = P2SHMultisigTransaction::script_to_p2sh(&script, "regtest");

        println!("P2SH address: {}", address);
        assert!(address.starts_with("2")); // P2SH addresses on testnet/regtest start with '2'
    }

    #[test]
    fn test_p2sh_transaction_creation() {
        let privkey1 = [0x11u8; 32];
        let privkey2 = [0x22u8; 32];

        let pubkey1 = privkey_to_pubkey(&privkey1).unwrap();
        let pubkey2 = privkey_to_pubkey(&privkey2).unwrap();

        let redeem_script = P2SHMultisigTransaction::create_2of2_redeem_script(&pubkey1, &pubkey2);

        let mut tx = P2SHMultisigTransaction::new(redeem_script);
        tx.add_input(TxInput::new([0x42u8; 32], 0));

        let output_spk = vec![vec![0x76, 0xa9, 0x14], vec![0x00; 22]].concat();
        tx.add_output(TxOutput::new(100_000_000, output_spk));

        let unsigned = tx.build_unsigned();
        assert!(!unsigned.is_empty());
    }

    #[test]
    fn test_p2sh_multisig_signing() {
        let privkey1 = [0x11u8; 32];
        let privkey2 = [0x22u8; 32];

        let pubkey1 = privkey_to_pubkey(&privkey1).unwrap();
        let pubkey2 = privkey_to_pubkey(&privkey2).unwrap();

        let redeem_script = P2SHMultisigTransaction::create_2of2_redeem_script(&pubkey1, &pubkey2);

        let mut tx = P2SHMultisigTransaction::new(redeem_script);
        tx.add_input(TxInput::new([0x42u8; 32], 0));
        tx.add_output(TxOutput::new(
            100_000_000,
            vec![vec![0x76, 0xa9, 0x14], vec![0x00; 22]].concat(),
        ));

        let signed = tx.sign(&[privkey1, privkey2], 0).unwrap();
        assert!(!signed.is_empty());

        // Verify it's not a segwit transaction
        assert_ne!(signed[4], 0x00);
        assert_ne!(signed[5], 0x01);
    }

    #[test]
    fn test_2of3_signing_with_2_keys() {
        let privkey1 = [0x11u8; 32];
        let privkey2 = [0x22u8; 32];
        let privkey3 = [0x33u8; 32];

        let pubkey1 = privkey_to_pubkey(&privkey1).unwrap();
        let pubkey2 = privkey_to_pubkey(&privkey2).unwrap();
        let pubkey3 = privkey_to_pubkey(&privkey3).unwrap();

        let redeem_script =
            P2SHMultisigTransaction::create_2of3_redeem_script(&pubkey1, &pubkey2, &pubkey3);

        let mut tx = P2SHMultisigTransaction::new(redeem_script);
        tx.add_input(TxInput::new([0x42u8; 32], 0));
        tx.add_output(TxOutput::new(
            100_000_000,
            vec![vec![0x76, 0xa9, 0x14], vec![0x00; 22]].concat(),
        ));

        // Sign with first two keys only (2-of-3)
        let signed = tx.sign(&[privkey1, privkey2], 0).unwrap();
        assert!(!signed.is_empty());
    }
}
