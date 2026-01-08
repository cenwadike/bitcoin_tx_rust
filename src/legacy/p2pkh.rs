//! Legacy P2PKH (Pay-to-Public-Key-Hash) Transaction Implementation
//!
//! This implements the original Bitcoin transaction type that was used before SegWit.
//! Note: This is for educational purposes. In production, use P2WPKH (SegWit) instead.

use crate::segwit::p2wpkh_single_input::{TxInput, TxOutput};
use crate::utils::*;

/// Legacy P2PKH Transaction Builder
///
/// Creates transactions in the original Bitcoin format (pre-SegWit).
/// These transactions do NOT use witness data and have signatures in scriptSig.
pub struct P2PKHTransaction {
    version: u32,
    inputs: Vec<TxInput>,
    outputs: Vec<TxOutput>,
    locktime: u32,
}

impl P2PKHTransaction {
    pub fn new() -> Self {
        Self {
            version: 2,
            inputs: Vec::new(),
            outputs: Vec::new(),
            locktime: 0,
        }
    }

    pub fn add_input(&mut self, input: TxInput) {
        self.inputs.push(input);
    }

    pub fn add_output(&mut self, output: TxOutput) {
        self.outputs.push(output);
    }

    /// Build unsigned transaction (scriptSig is empty)
    pub fn build_unsigned(&self) -> Vec<u8> {
        let mut tx = Vec::new();

        // Version
        tx.extend_from_slice(&self.version.to_le_bytes());

        // Input count
        tx.extend_from_slice(&varint_len(&vec![0u8; self.inputs.len()]));

        // Inputs (with empty scriptSig)
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

    /// Sign the transaction (legacy style - signature goes in scriptSig)
    pub fn sign(
        &self,
        privkey: &[u8; 32],
        pubkey: &[u8],
        input_index: usize,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if input_index >= self.inputs.len() {
            return Err("Input index out of bounds".into());
        }

        let sighash_type = 1u32; // SIGHASH_ALL

        // Create the scriptPubKey for the input being signed
        let pk_hash = hash160(pubkey);
        let mut script_pubkey = vec![0x76, 0xa9, 0x14]; // OP_DUP OP_HASH160 <20 bytes>
        script_pubkey.extend_from_slice(&pk_hash);
        script_pubkey.extend_from_slice(&[0x88, 0xac]); // OP_EQUALVERIFY OP_CHECKSIG

        // Build transaction with scriptPubKey in place of scriptSig
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
                // For the input being signed, use the scriptPubKey
                tx_to_sign.extend_from_slice(&varint_len(&script_pubkey));
                tx_to_sign.extend_from_slice(&script_pubkey);
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

        // Sighash flag (4 bytes for signing)
        tx_to_sign.extend_from_slice(&sighash_type.to_le_bytes());

        // Hash and sign
        let sighash = hash256(&tx_to_sign);
        let mut signature = sign_hash(privkey, &sighash)?;
        signature.push(0x01); // Append SIGHASH_ALL (1 byte)

        // Build scriptSig
        let mut script_sig = Vec::new();
        script_sig.extend_from_slice(&pushbytes(&signature));
        script_sig.extend_from_slice(&pushbytes(pubkey));

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
                // Add the signature
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_legacy_p2pkh_transaction() {
        let privkey = [0x11u8; 32];
        let pubkey = privkey_to_pubkey(&privkey).unwrap();

        let mut tx = P2PKHTransaction::new();
        tx.add_input(TxInput::new([0x42u8; 32], 0));
        tx.add_output(TxOutput::new(
            100_000_000,
            vec![vec![0x76, 0xa9, 0x14], vec![0x00; 22]].concat(),
        ));

        let unsigned = tx.build_unsigned();
        assert!(!unsigned.is_empty());

        let signed = tx.sign(&privkey, &pubkey, 0).unwrap();
        assert!(!signed.is_empty());
        assert!(signed.len() > unsigned.len()); // Signed should be larger
    }

    #[test]
    fn test_legacy_no_segwit_marker() {
        let privkey = [0x11u8; 32];
        let pubkey = privkey_to_pubkey(&privkey).unwrap();

        let mut tx = P2PKHTransaction::new();
        tx.add_input(TxInput::new([0x42u8; 32], 0));
        tx.add_output(TxOutput::new(
            100_000_000,
            vec![vec![0x76, 0xa9, 0x14], vec![0x00; 22]].concat(),
        ));

        let signed = tx.sign(&privkey, &pubkey, 0).unwrap();

        // Check that there's NO segwit marker (0x00 0x01) after version
        assert_ne!(signed[4], 0x00);
        assert_ne!(signed[5], 0x01);
    }
}
