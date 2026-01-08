use crate::segwit::p2wpkh_single_input::{TxInput, TxOutput};
use crate::utils::*;

/// P2WPKH Transaction with Multiple Inputs
pub struct MultiInputP2WPKHTransaction {
    version: u32,
    inputs: Vec<TxInput>,
    outputs: Vec<TxOutput>,
    locktime: u32,
}

impl MultiInputP2WPKHTransaction {
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

    /// Create the unsigned transaction
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

    /// Create the sighash preimage for a specific input (BIP143)
    fn create_sighash_preimage(
        &self,
        input_index: usize,
        pubkey: &[u8],
        input_value: u64,
        sighash_type: u32,
    ) -> Vec<u8> {
        let input = &self.inputs[input_index];

        // Create scriptCode (P2PKH-like script)
        let pk_hash = hash160(pubkey);
        let mut scriptcode = vec![0x76, 0xa9, 0x14]; // OP_DUP OP_HASH160 <20 bytes>
        scriptcode.extend_from_slice(&pk_hash);
        scriptcode.extend_from_slice(&[0x88, 0xac]); // OP_EQUALVERIFY OP_CHECKSIG

        // Serialize all outputs
        let mut outputs_serialized = Vec::new();
        for output in &self.outputs {
            outputs_serialized.extend_from_slice(&output.serialize());
        }

        // Create hashPrevouts (hash of all input outpoints)
        let mut prevouts = Vec::new();
        for inp in &self.inputs {
            let mut txid_le = inp.txid;
            txid_le.reverse();
            prevouts.extend_from_slice(&txid_le);
            prevouts.extend_from_slice(&inp.vout.to_le_bytes());
        }
        let hash_prevouts = hash256(&prevouts);

        // Create hashSequence (hash of all input sequences)
        let mut sequences = Vec::new();
        for inp in &self.inputs {
            sequences.extend_from_slice(&inp.sequence.to_le_bytes());
        }
        let hash_sequence = hash256(&sequences);

        // Create hashOutputs
        let hash_outputs = hash256(&outputs_serialized);

        // Build the sighash preimage
        let mut preimage = Vec::new();

        // Version
        preimage.extend_from_slice(&self.version.to_le_bytes());

        // hashPrevouts
        preimage.extend_from_slice(&hash_prevouts);

        // hashSequence
        preimage.extend_from_slice(&hash_sequence);

        // Outpoint (txid + vout of the input being signed)
        let mut txid_le = input.txid;
        txid_le.reverse();
        preimage.extend_from_slice(&txid_le);
        preimage.extend_from_slice(&input.vout.to_le_bytes());

        // scriptCode with length
        preimage.extend_from_slice(&varint_len(&scriptcode));
        preimage.extend_from_slice(&scriptcode);

        // Value
        preimage.extend_from_slice(&input_value.to_le_bytes());

        // Sequence
        preimage.extend_from_slice(&input.sequence.to_le_bytes());

        // hashOutputs
        preimage.extend_from_slice(&hash_outputs);

        // Locktime
        preimage.extend_from_slice(&self.locktime.to_le_bytes());

        // Sighash type
        preimage.extend_from_slice(&sighash_type.to_le_bytes());

        preimage
    }

    /// Sign the transaction with multiple inputs
    /// Each input requires its own private key, public key, and input value
    pub fn sign(
        &self,
        input_data: &[(Vec<u8>, Vec<u8>, u64)], // (privkey, pubkey, value) for each input
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if input_data.len() != self.inputs.len() {
            return Err("Number of signing keys must match number of inputs".into());
        }

        let sighash_type = 1u32; // SIGHASH_ALL

        // Create signatures for each input
        let mut witnesses = Vec::new();
        for (i, (privkey, pubkey, value)) in input_data.iter().enumerate() {
            // Create sighash preimage
            let mut privkey_array = [0u8; 32];
            privkey_array.copy_from_slice(privkey);

            let preimage = self.create_sighash_preimage(i, pubkey, *value, sighash_type);

            // Hash the preimage
            let sighash = hash256(&preimage);

            // Sign the hash
            let mut signature = sign_hash(&privkey_array, &sighash)?;

            // Append SIGHASH_ALL flag
            signature.push(0x01);

            // Build witness for this input
            let mut witness = Vec::new();
            witness.push(0x02); // 2 stack items
            witness.extend_from_slice(&pushbytes(&signature));
            witness.extend_from_slice(&pushbytes(pubkey));

            witnesses.push(witness);
        }

        // Build final signed transaction
        let mut signed_tx = Vec::new();

        // Version
        signed_tx.extend_from_slice(&self.version.to_le_bytes());

        // Marker and flag (segwit)
        signed_tx.push(0x00);
        signed_tx.push(0x01);

        // Input count
        signed_tx.extend_from_slice(&varint_len(&vec![0u8; self.inputs.len()]));

        // Inputs
        for input in &self.inputs {
            signed_tx.extend_from_slice(&input.serialize());
        }

        // Output count
        signed_tx.extend_from_slice(&varint_len(&vec![0u8; self.outputs.len()]));

        // Outputs
        for output in &self.outputs {
            signed_tx.extend_from_slice(&output.serialize());
        }

        // Witnesses (one for each input, in order)
        for witness in witnesses {
            signed_tx.extend_from_slice(&witness);
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
    fn test_multi_input_transaction() {
        let privkey1 = [0x11u8; 32];
        let privkey2 = [0x22u8; 32];

        let pubkey1 = privkey_to_pubkey(&privkey1).unwrap();
        let pubkey2 = privkey_to_pubkey(&privkey2).unwrap();

        let mut tx = MultiInputP2WPKHTransaction::new();

        // Add two inputs
        tx.add_input(TxInput::new([0x42u8; 32], 0));
        tx.add_input(TxInput::new([0x43u8; 32], 0));

        // Add outputs
        tx.add_output(TxOutput::new(
            100_000_000,
            vec![vec![0x00, 0x14], vec![0x00; 20]].concat(),
        ));
        tx.add_output(TxOutput::new(
            50_000_000,
            vec![vec![0x00, 0x14], vec![0x00; 20]].concat(),
        ));

        // Sign with both keys
        let input_data = vec![
            (privkey1.to_vec(), pubkey1, 100_000_000),
            (privkey2.to_vec(), pubkey2, 100_000_000),
        ];

        let signed = tx.sign(&input_data).unwrap();
        assert!(!signed.is_empty());

        // Verify segwit marker and flag
        assert_eq!(signed[4], 0x00);
        assert_eq!(signed[5], 0x01);
    }

    #[test]
    fn test_multi_input_witness_order() {
        let privkey1 = [0x11u8; 32];
        let privkey2 = [0x22u8; 32];
        let privkey3 = [0x33u8; 32];

        let pubkey1 = privkey_to_pubkey(&privkey1).unwrap();
        let pubkey2 = privkey_to_pubkey(&privkey2).unwrap();
        let pubkey3 = privkey_to_pubkey(&privkey3).unwrap();

        let mut tx = MultiInputP2WPKHTransaction::new();

        tx.add_input(TxInput::new([0x01u8; 32], 0));
        tx.add_input(TxInput::new([0x02u8; 32], 0));
        tx.add_input(TxInput::new([0x03u8; 32], 0));

        tx.add_output(TxOutput::new(
            200_000_000,
            vec![vec![0x00, 0x14], vec![0x00; 20]].concat(),
        ));

        let input_data = vec![
            (privkey1.to_vec(), pubkey1, 100_000_000),
            (privkey2.to_vec(), pubkey2, 100_000_000),
            (privkey3.to_vec(), pubkey3, 100_000_000),
        ];

        let signed = tx.sign(&input_data).unwrap();
        assert!(!signed.is_empty());
    }

    #[test]
    fn test_mismatched_input_count() {
        let privkey1 = [0x11u8; 32];
        let pubkey1 = privkey_to_pubkey(&privkey1).unwrap();

        let mut tx = MultiInputP2WPKHTransaction::new();
        tx.add_input(TxInput::new([0x42u8; 32], 0));
        tx.add_input(TxInput::new([0x43u8; 32], 0));

        tx.add_output(TxOutput::new(
            100_000_000,
            vec![vec![0x00, 0x14], vec![0x00; 20]].concat(),
        ));

        // Only provide one key for two inputs
        let input_data = vec![(privkey1.to_vec(), pubkey1, 100_000_000)];

        let result = tx.sign(&input_data);
        assert!(result.is_err());
    }
}
