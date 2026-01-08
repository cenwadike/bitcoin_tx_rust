use crate::utils::*;

/// Represents a transaction input
#[derive(Debug, Clone)]
pub struct TxInput {
    pub txid: [u8; 32],
    pub vout: u32,
    pub sequence: u32,
}

impl TxInput {
    pub fn new(txid: [u8; 32], vout: u32) -> Self {
        Self {
            txid,
            vout,
            sequence: 0xffffffff,
        }
    }

    /// Serialize the input for the transaction (without scriptSig for unsigned tx)
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Txid (little endian)
        let mut txid_le = self.txid;
        txid_le.reverse();
        data.extend_from_slice(&txid_le);

        // Vout (little endian)
        data.extend_from_slice(&self.vout.to_le_bytes());

        // Empty scriptSig for segwit
        data.push(0x00);

        // Sequence
        data.extend_from_slice(&self.sequence.to_le_bytes());

        data
    }
}

/// Represents a transaction output
#[derive(Debug, Clone)]
pub struct TxOutput {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

impl TxOutput {
    pub fn new(value: u64, script_pubkey: Vec<u8>) -> Self {
        Self {
            value,
            script_pubkey,
        }
    }

    /// Serialize the output
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Value (little endian)
        data.extend_from_slice(&self.value.to_le_bytes());

        // ScriptPubKey with length prefix
        data.extend_from_slice(&varint_len(&self.script_pubkey));
        data.extend_from_slice(&self.script_pubkey);

        data
    }
}

/// P2WPKH Transaction Builder
pub struct P2WPKHTransaction {
    version: u32,
    inputs: Vec<TxInput>,
    outputs: Vec<TxOutput>,
    locktime: u32,
}

impl P2WPKHTransaction {
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
    pub fn create_sighash_preimage(
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

    /// Sign the transaction (single input version)
    pub fn sign(
        &self,
        privkey: &[u8; 32],
        pubkey: &[u8],
        input_value: u64,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // SIGHASH_ALL = 0x01
        let sighash_type = 1u32;

        // Create sighash preimage for input 0
        let preimage = self.create_sighash_preimage(0, pubkey, input_value, sighash_type);

        // Hash the preimage
        let sighash = hash256(&preimage);

        // Sign the hash
        let mut signature = sign_hash(privkey, &sighash)?;

        // Append SIGHASH_ALL flag
        signature.push(0x01);

        // Build witness
        let mut witness = Vec::new();
        witness.push(0x02); // 2 stack items
        witness.extend_from_slice(&pushbytes(&signature));
        witness.extend_from_slice(&pushbytes(pubkey));

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

        // Witness
        signed_tx.extend_from_slice(&witness);

        // Locktime
        signed_tx.extend_from_slice(&self.locktime.to_le_bytes());

        Ok(signed_tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_p2wpkh_transaction() {
        let mut tx = P2WPKHTransaction::new();

        let input = TxInput::new([0u8; 32], 0);
        tx.add_input(input);

        let output = TxOutput::new(100_000_000, vec![vec![0x00, 0x14], vec![0x00; 20]].concat());
        tx.add_output(output);

        let unsigned = tx.build_unsigned();
        assert!(!unsigned.is_empty());
        assert_eq!(&unsigned[0..4], &[0x02, 0x00, 0x00, 0x00]); // Version 2
    }

    #[test]
    fn test_sign_p2wpkh_transaction() {
        let privkey = [0x11u8; 32];
        let pubkey = privkey_to_pubkey(&privkey).unwrap();

        let mut tx = P2WPKHTransaction::new();
        let input = TxInput::new([0x42u8; 32], 0);
        tx.add_input(input);

        let output = TxOutput::new(100_000_000, vec![vec![0x00, 0x14], vec![0x00; 20]].concat());
        tx.add_output(output);

        let signed = tx.sign(&privkey, &pubkey, 200_000_000).unwrap();
        assert!(!signed.is_empty());

        // Check for marker and flag
        assert_eq!(signed[4], 0x00); // marker
        assert_eq!(signed[5], 0x01); // flag
    }

    #[test]
    fn test_tx_input_serialization() {
        let input = TxInput::new([0x42u8; 32], 5);
        let serialized = input.serialize();

        // Check TXID is reversed (little endian)
        assert_eq!(serialized[0], 0x42);

        // Check vout
        assert_eq!(serialized[32..36], [0x05, 0x00, 0x00, 0x00]);

        // Check empty scriptSig
        assert_eq!(serialized[36], 0x00);
    }

    #[test]
    fn test_tx_output_serialization() {
        let output = TxOutput::new(50_000, vec![0x76, 0xa9]);
        let serialized = output.serialize();

        // Check value (little endian)
        assert_eq!(&serialized[0..8], &50_000u64.to_le_bytes());

        // Check script length
        assert_eq!(serialized[8], 0x02);
    }
}
