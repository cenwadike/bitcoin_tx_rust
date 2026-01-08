//! P2TR (Pay-to-Taproot) Transaction Implementation - FINAL FIX

use crate::crypto::{tagged_hash, varint_encode};
use crate::segwit::p2wpkh_single_input::{TxInput, TxOutput};
use crate::taproot::schnorr::*;
use crate::taproot::taptree::*;
use crate::utils::*;

const TAPSCRIPT_VER: u8 = 0xc0;

/// Compute the control block for a script-path spend (BIP-341)
fn compute_control_block(
    internal_pubkey: &[u8],
    merkle_path: &[[u8; 32]],
    output_parity: bool,
    leaf_version: u8,
) -> Vec<u8> {
    let mut control_block = Vec::new();

    // First byte: leaf_version | parity_bit
    let parity_bit = if output_parity { 1 } else { 0 };
    control_block.push(leaf_version | parity_bit);

    // Internal pubkey (32 bytes)
    control_block.extend_from_slice(internal_pubkey);

    // Merkle proof: each branch hash (32 bytes each)
    for branch in merkle_path {
        control_block.extend_from_slice(branch);
    }

    control_block
}

/// P2TR Transaction (Key Path Spend)
pub struct P2TRKeyPathTransaction {
    version: u32,
    inputs: Vec<TxInput>,
    outputs: Vec<TxOutput>,
    locktime: u32,
    internal_pubkey: Vec<u8>,
    merkle_root: Option<Vec<u8>>,
}

impl P2TRKeyPathTransaction {
    pub fn new(internal_pubkey: Vec<u8>, merkle_root: Option<Vec<u8>>) -> Self {
        Self {
            version: 2,
            inputs: Vec::new(),
            outputs: Vec::new(),
            locktime: 0,
            internal_pubkey,
            merkle_root,
        }
    }

    pub fn add_input(&mut self, input: TxInput) {
        self.inputs.push(input);
    }

    pub fn add_output(&mut self, output: TxOutput) {
        self.outputs.push(output);
    }

    pub fn get_taproot_pubkey(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let merkle_root = self.merkle_root.as_deref();
        let (_, tweaked_pubkey) = taproot_tweak_pubkey(&self.internal_pubkey, merkle_root)?;
        Ok(tweaked_pubkey)
    }

    pub fn build_unsigned(&self) -> Vec<u8> {
        let mut tx = Vec::new();

        tx.extend_from_slice(&self.version.to_le_bytes());
        tx.extend_from_slice(&varint_len(&vec![0u8; self.inputs.len()]));

        for input in &self.inputs {
            tx.extend_from_slice(&input.serialize());
        }

        tx.extend_from_slice(&varint_len(&vec![0u8; self.outputs.len()]));

        for output in &self.outputs {
            tx.extend_from_slice(&output.serialize());
        }

        tx.extend_from_slice(&self.locktime.to_le_bytes());

        tx
    }

    fn create_taproot_sighash(
        &self,
        input_index: usize,
        input_values: &[u64],
        input_scriptpubkeys: &[Vec<u8>],
        sighash_type: u8,
    ) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        if input_index >= self.inputs.len() {
            return Err("Input index out of bounds".into());
        }

        let mut sig_msg = Vec::new();

        sig_msg.push(0x00); // epoch
        sig_msg.push(sighash_type);

        sig_msg.extend_from_slice(&self.version.to_le_bytes());
        sig_msg.extend_from_slice(&self.locktime.to_le_bytes());

        let mut prevouts = Vec::new();
        for input in &self.inputs {
            let mut txid_le = input.txid;
            txid_le.reverse();
            prevouts.extend_from_slice(&txid_le);
            prevouts.extend_from_slice(&input.vout.to_le_bytes());
        }
        sig_msg.extend_from_slice(&sha256(&prevouts));

        let mut amounts = Vec::new();
        for &value in input_values {
            amounts.extend_from_slice(&value.to_le_bytes());
        }
        sig_msg.extend_from_slice(&sha256(&amounts));

        let mut scriptpubkeys = Vec::new();
        for spk in input_scriptpubkeys {
            scriptpubkeys.extend_from_slice(&varint_len(spk));
            scriptpubkeys.extend_from_slice(spk);
        }
        sig_msg.extend_from_slice(&sha256(&scriptpubkeys));

        let mut sequences = Vec::new();
        for input in &self.inputs {
            sequences.extend_from_slice(&input.sequence.to_le_bytes());
        }
        sig_msg.extend_from_slice(&sha256(&sequences));

        let mut outputs = Vec::new();
        for output in &self.outputs {
            outputs.extend_from_slice(&output.serialize());
        }
        sig_msg.extend_from_slice(&sha256(&outputs));

        sig_msg.push(0x00); // spend_type: key path
        sig_msg.extend_from_slice(&(input_index as u32).to_le_bytes());

        Ok(tagged_hash("TapSighash", &sig_msg))
    }

    pub fn sign(
        &self,
        internal_privkey: &[u8; 32],
        input_values: &[u64],
        input_scriptpubkeys: &[Vec<u8>],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if self.inputs.len() != 1 {
            return Err("Currently only single input supported".into());
        }

        let merkle_root = self.merkle_root.as_deref();
        let tweaked_privkey = taproot_tweak_privkey(internal_privkey, merkle_root)?;

        let sighash = self.create_taproot_sighash(0, input_values, input_scriptpubkeys, 0x00)?;

        let signature = schnorr_sign(&tweaked_privkey, &sighash)?;

        // Witness: single element (signature + SIGHASH_DEFAULT implied)
        let witness_data = pushbytes(&signature);

        let mut signed_tx = Vec::new();

        signed_tx.extend_from_slice(&self.version.to_le_bytes());
        signed_tx.push(0x00); // marker
        signed_tx.push(0x01); // flag

        signed_tx.extend_from_slice(&varint_len(&[0u8]));
        for input in &self.inputs {
            signed_tx.extend_from_slice(&input.serialize());
        }

        signed_tx.extend_from_slice(&varint_len(&vec![0u8; self.outputs.len()]));
        for output in &self.outputs {
            signed_tx.extend_from_slice(&output.serialize());
        }

        // Witness for input 0
        signed_tx.extend_from_slice(&varint_len(&[0u8])); // 1 witness item
        signed_tx.extend_from_slice(&varint_len(&witness_data));
        signed_tx.extend_from_slice(&witness_data);

        signed_tx.extend_from_slice(&self.locktime.to_le_bytes());

        Ok(signed_tx)
    }
}

/// P2TR Transaction (Script Path Spend)
pub struct P2TRScriptPathTransaction {
    version: u32,
    inputs: Vec<TxInput>,
    outputs: Vec<TxOutput>,
    locktime: u32,
    internal_pubkey: Vec<u8>,
    tap_leaf: TapLeaf,
    merkle_path: Vec<[u8; 32]>,
    output_parity: bool, // parity of the final tweaked pubkey (from taproot_tweak_pubkey)
}

impl P2TRScriptPathTransaction {
    pub fn new(
        internal_pubkey: Vec<u8>,
        tap_leaf: TapLeaf,
        merkle_path: Vec<[u8; 32]>,
        output_parity: bool,
    ) -> Self {
        Self {
            version: 2,
            inputs: Vec::new(),
            outputs: Vec::new(),
            locktime: 0,
            internal_pubkey,
            tap_leaf,
            merkle_path,
            output_parity,
        }
    }

    pub fn add_input(&mut self, input: TxInput) {
        self.inputs.push(input);
    }

    pub fn add_output(&mut self, output: TxOutput) {
        self.outputs.push(output);
    }

    fn create_script_path_sighash(
        &self,
        input_index: usize,
        input_values: &[u64],
        input_scriptpubkeys: &[Vec<u8>],
        sighash_type: u8,
    ) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        if input_index >= self.inputs.len() {
            return Err("Input index out of bounds".into());
        }

        let mut sig_msg = Vec::new();

        sig_msg.push(0x00); // epoch
        sig_msg.push(sighash_type);

        sig_msg.extend_from_slice(&self.version.to_le_bytes());
        sig_msg.extend_from_slice(&self.locktime.to_le_bytes());

        let mut prevouts = Vec::new();
        for input in &self.inputs {
            let mut txid_le = input.txid;
            txid_le.reverse();
            prevouts.extend_from_slice(&txid_le);
            prevouts.extend_from_slice(&input.vout.to_le_bytes());
        }
        sig_msg.extend_from_slice(&sha256(&prevouts));

        let mut amounts = Vec::new();
        for &value in input_values {
            amounts.extend_from_slice(&value.to_le_bytes());
        }
        sig_msg.extend_from_slice(&sha256(&amounts));

        let mut scriptpubkeys = Vec::new();
        for spk in input_scriptpubkeys {
            scriptpubkeys.extend_from_slice(&varint_len(spk));
            scriptpubkeys.extend_from_slice(spk);
        }
        sig_msg.extend_from_slice(&sha256(&scriptpubkeys));

        let mut sequences = Vec::new();
        for input in &self.inputs {
            sequences.extend_from_slice(&input.sequence.to_le_bytes());
        }
        sig_msg.extend_from_slice(&sha256(&sequences));

        let mut outputs = Vec::new();
        for output in &self.outputs {
            outputs.extend_from_slice(&output.serialize());
        }
        sig_msg.extend_from_slice(&sha256(&outputs));

        sig_msg.push(0x02); // spend_type: script path
        sig_msg.extend_from_slice(&(input_index as u32).to_le_bytes());

        // Script-path specific fields
        sig_msg.extend_from_slice(&self.tap_leaf.leaf_hash());
        sig_msg.push(0x00); // key_version
        sig_msg.extend_from_slice(&0xffffffffu32.to_le_bytes()); // codeseparator_pos

        Ok(tagged_hash("TapSighash", &sig_msg))
    }

    pub fn sign(
        &self,
        privkey: &[u8; 32],
        input_values: &[u64],
        input_scriptpubkeys: &[Vec<u8>],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if self.inputs.len() != 1 {
            return Err("Currently only single input supported".into());
        }

        let sighash =
            self.create_script_path_sighash(0, input_values, input_scriptpubkeys, 0x00)?;
        let signature = schnorr_sign(privkey, &sighash)?;

        let control_block = compute_control_block(
            &self.internal_pubkey,
            &self.merkle_path,
            self.output_parity,
            TAPSCRIPT_VER,
        );

        // ============================================================================
        // CRITICAL FIX: Use raw data with varint length prefixes
        // NOT script-style pushbytes encoding
        // ============================================================================

        let mut signed_tx = Vec::new();

        // Version
        signed_tx.extend_from_slice(&self.version.to_le_bytes());

        // SegWit marker + flag
        signed_tx.push(0x00);
        signed_tx.push(0x01);

        // Input count
        signed_tx.extend_from_slice(&varint_encode(1));

        // Input
        signed_tx.extend_from_slice(&self.inputs[0].serialize());

        // Output count
        signed_tx.extend_from_slice(&varint_encode(self.outputs.len() as u64));

        // Outputs
        for output in &self.outputs {
            signed_tx.extend_from_slice(&output.serialize());
        }

        // ============================================================================
        // Witness Structure (BIP 141 + BIP 341)
        // ============================================================================
        // For script path spend, witness stack contains exactly 3 items:
        //   1. Signature (64 bytes for Schnorr)
        //   2. Script (the tapscript being executed)
        //   3. Control block (version+parity | internal_key | merkle_path)
        //
        // Each item is encoded as:
        //   <item_length_as_varint><item_data>
        //
        // DO NOT use pushbytes() - that adds Bitcoin Script push opcodes,
        // but witness items use CompactSize length encoding directly.
        // ============================================================================

        // Number of witness stack items
        signed_tx.extend_from_slice(&varint_encode(3));

        // Witness Item 1: Signature
        // Schnorr signatures are 64 bytes (no DER encoding, no sighash type appended for DEFAULT)
        signed_tx.extend_from_slice(&varint_encode(signature.len() as u64));
        signed_tx.extend_from_slice(&signature);

        // Witness Item 2: Script
        // The actual tapscript (e.g., <pubkey> OP_CHECKSIG)
        signed_tx.extend_from_slice(&varint_encode(self.tap_leaf.script.len() as u64));
        signed_tx.extend_from_slice(&self.tap_leaf.script);

        // Witness Item 3: Control Block
        // Format: [version+parity(1)] [internal_pubkey(32)] [merkle_path(32*n)]
        signed_tx.extend_from_slice(&varint_encode(control_block.len() as u64));
        signed_tx.extend_from_slice(&control_block);

        // Locktime
        signed_tx.extend_from_slice(&self.locktime.to_le_bytes());

        Ok(signed_tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p2tr_key_path_creation() {
        let internal_privkey = [0x01u8; 32];
        let internal_pubkey = schnorr_pubkey_gen(&internal_privkey).unwrap();

        let mut tx = P2TRKeyPathTransaction::new(internal_pubkey, None);
        tx.add_input(TxInput::new([0x42u8; 32], 0));
        tx.add_output(TxOutput::new(
            100_000_000,
            [vec![0x51, 0x20], vec![0x00; 32]].concat(),
        ));

        let unsigned = tx.build_unsigned();
        assert!(!unsigned.is_empty());
    }

    #[test]
    fn test_taproot_pubkey_derivation() {
        let internal_privkey = [0x01u8; 32];
        let internal_pubkey = schnorr_pubkey_gen(&internal_privkey).unwrap();

        let tx = P2TRKeyPathTransaction::new(internal_pubkey, None);
        let taproot_pubkey = tx.get_taproot_pubkey().unwrap();

        assert_eq!(taproot_pubkey.len(), 32);
    }
}
