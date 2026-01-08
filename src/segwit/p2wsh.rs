use crate::segwit::p2wpkh_single_input::{TxInput, TxOutput};
use crate::utils::*;

/// P2WSH Multisig Transaction Builder
pub struct P2WSHMultisigTransaction {
    version: u32,
    inputs: Vec<TxInput>,
    outputs: Vec<TxOutput>,
    locktime: u32,
    redeem_script: Vec<u8>,
}

impl P2WSHMultisigTransaction {
    /// Create a new P2WSH multisig transaction with the given redeem script
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

    pub fn add_input(&mut self, input: TxInput) {
        self.inputs.push(input);
    }

    pub fn add_output(&mut self, output: TxOutput) {
        self.outputs.push(output);
    }

    pub fn get_redeem_script(&self) -> &[u8] {
        &self.redeem_script
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

    /// Create the sighash preimage for P2WSH (BIP143)
    fn create_sighash_preimage(
        &self,
        input_index: usize,
        input_value: u64,
        sighash_type: u32,
    ) -> Vec<u8> {
        let input = &self.inputs[input_index];

        // For P2WSH, the scriptCode is the redeemScript
        let scriptcode = &self.redeem_script;

        // Serialize all outputs
        let mut outputs_serialized = Vec::new();
        for output in &self.outputs {
            outputs_serialized.extend_from_slice(&output.serialize());
        }

        // Create hashPrevouts
        let mut prevouts = Vec::new();
        for inp in &self.inputs {
            let mut txid_le = inp.txid;
            txid_le.reverse();
            prevouts.extend_from_slice(&txid_le);
            prevouts.extend_from_slice(&inp.vout.to_le_bytes());
        }
        let hash_prevouts = hash256(&prevouts);

        // Create hashSequence
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

        // Outpoint
        let mut txid_le = input.txid;
        txid_le.reverse();
        preimage.extend_from_slice(&txid_le);
        preimage.extend_from_slice(&input.vout.to_le_bytes());

        // scriptCode with length
        preimage.extend_from_slice(&varint_len(scriptcode));
        preimage.extend_from_slice(scriptcode);

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

    /// Sign the transaction with multiple private keys (for multisig)
    /// For a 2-of-2, provide 2 private keys
    pub fn sign(
        &self,
        privkeys: &[[u8; 32]],
        input_value: u64,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if self.inputs.len() != 1 {
            return Err("This implementation currently supports single input only".into());
        }

        let sighash_type = 1u32; // SIGHASH_ALL

        // Create sighash preimage
        let preimage = self.create_sighash_preimage(0, input_value, sighash_type);

        // Hash the preimage
        let sighash = hash256(&preimage);

        // Create signatures for each private key
        let mut signatures = Vec::new();
        for privkey in privkeys {
            let mut signature = sign_hash(privkey, &sighash)?;
            signature.push(0x01); // Append SIGHASH_ALL
            signatures.push(signature);
        }

        // Build witness
        let mut witness = Vec::new();

        // Number of witness stack items (extra 0 for CHECKMULTISIG bug + sigs + script)
        witness.push((signatures.len() + 2) as u8);

        // Add extra "00" for the CHECKMULTISIG bug
        witness.push(0x00);

        // Add signatures
        for sig in signatures {
            witness.extend_from_slice(&pushbytes(&sig));
        }

        // Add redeem script
        witness.extend_from_slice(&pushbytes(&self.redeem_script));

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
    use std::vec;

    use super::*;

    #[test]
    fn test_create_2of2_redeem_script() {
        let privkey1 = [0x11u8; 32];
        let privkey2 = [0x22u8; 32];

        let pubkey1 = privkey_to_pubkey(&privkey1).unwrap();
        let pubkey2 = privkey_to_pubkey(&privkey2).unwrap();

        let script = P2WSHMultisigTransaction::create_2of2_redeem_script(&pubkey1, &pubkey2);

        // Check script structure: OP_2 <pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG
        assert_eq!(script[0], 0x52); // OP_2
        assert_eq!(script[script.len() - 2], 0x52); // OP_2
        assert_eq!(script[script.len() - 1], 0xae); // OP_CHECKMULTISIG

        // Expected length: 1 + 1 + 33 + 1 + 33 + 1 + 1 = 71
        assert_eq!(script.len(), 71);
    }

    #[test]
    fn test_create_multisig_redeem_script() {
        let pubkeys = vec![vec![0x03; 33], vec![0x04; 33], vec![0x05; 33]];

        let script = P2WSHMultisigTransaction::create_multisig_redeem_script(2, &pubkeys).unwrap();

        // OP_2 for m=2
        assert_eq!(script[0], 0x52);
        // OP_3 for n=3
        assert_eq!(script[script.len() - 2], 0x53);
        // OP_CHECKMULTISIG
        assert_eq!(script[script.len() - 1], 0xae);
    }

    #[test]
    fn test_invalid_multisig_m() {
        let pubkeys = vec![vec![0x03; 33], vec![0x04; 33]];

        // m = 0 should fail
        let result = P2WSHMultisigTransaction::create_multisig_redeem_script(0, &pubkeys);
        assert!(result.is_err());

        // m > n should fail
        let result = P2WSHMultisigTransaction::create_multisig_redeem_script(3, &pubkeys);
        assert!(result.is_err());
    }

    #[test]
    fn test_p2wsh_transaction_creation() {
        let privkey1 = [0x11u8; 32];
        let privkey2 = [0x22u8; 32];

        let pubkey1 = privkey_to_pubkey(&privkey1).unwrap();
        let pubkey2 = privkey_to_pubkey(&privkey2).unwrap();

        let redeem_script = P2WSHMultisigTransaction::create_2of2_redeem_script(&pubkey1, &pubkey2);

        let mut tx = P2WSHMultisigTransaction::new(redeem_script);
        tx.add_input(TxInput::new([0x42u8; 32], 0));
        tx.add_output(TxOutput::new(
            100_000_000,
            vec![vec![0x76, 0xa9, 0x14], vec![0x00; 22]].concat(),
        ));

        let unsigned = tx.build_unsigned();
        assert!(!unsigned.is_empty());
    }

    #[test]
    fn test_sign_p2wsh_multisig() {
        let privkey1 = [0x11u8; 32];
        let privkey2 = [0x22u8; 32];

        let pubkey1 = privkey_to_pubkey(&privkey1).unwrap();
        let pubkey2 = privkey_to_pubkey(&privkey2).unwrap();

        let redeem_script = P2WSHMultisigTransaction::create_2of2_redeem_script(&pubkey1, &pubkey2);

        let mut tx = P2WSHMultisigTransaction::new(redeem_script);
        tx.add_input(TxInput::new([0x42u8; 32], 0));
        tx.add_output(TxOutput::new(
            100_000_000,
            vec![vec![0x76, 0xa9, 0x14], vec![0x00; 22]].concat(),
        ));

        let signed = tx.sign(&[privkey1, privkey2], 200_000_000).unwrap();
        assert!(!signed.is_empty());

        // Verify segwit marker and flag
        assert_eq!(signed[4], 0x00);
        assert_eq!(signed[5], 0x01);
    }

    #[test]
    fn test_1of1_multisig() {
        let privkey = [0x11u8; 32];
        let pubkey = privkey_to_pubkey(&privkey).unwrap();

        let script =
            P2WSHMultisigTransaction::create_multisig_redeem_script(1, &[pubkey.clone()]).unwrap();

        let mut tx = P2WSHMultisigTransaction::new(script);
        tx.add_input(TxInput::new([0x42u8; 32], 0));
        tx.add_output(TxOutput::new(
            100_000_000,
            [vec![0x00, 0x14], vec![0x00; 20]].concat(),
        ));

        let signed = tx.sign(&[privkey], 200_000_000).unwrap();
        assert!(!signed.is_empty());
    }
}
