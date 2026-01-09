//! P2WSH Multisig Transaction with Trait Support
//!
//! This implements SegWit P2WSH multisig with full trait support

use crate::sighash::{SegwitV0Sighash, SighashFlag, SighashInput, SighashOutput};
use crate::timelocks::{LockTime, OpCheckLockTimeVerify, OpCheckSequenceVerify, Sequence};
use crate::transaction::*;
use crate::utils::*;

/// P2WSH Multisig Transaction with full trait support
#[derive(Debug, Clone)]
pub struct P2WSHMultisigTransaction {
    version: u32,
    inputs: Vec<P2WSHTxInput>,
    outputs: Vec<P2WSHTxOutput>,
    locktime: LockTime,
    redeem_script: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct P2WSHTxInput {
    pub txid: [u8; 32],
    pub vout: u32,
    pub sequence: Sequence,
    pub sighash_flag: SighashFlag,
    pub amount: u64,
}

#[derive(Debug, Clone)]
pub struct P2WSHTxOutput {
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
}

impl P2WSHMultisigTransaction {
    pub fn new(redeem_script: Vec<u8>) -> Self {
        Self {
            version: 2,
            inputs: Vec::new(),
            outputs: Vec::new(),
            locktime: LockTime::None,
            redeem_script,
        }
    }

    /// Create a 2-of-2 multisig redeem script
    pub fn create_2of2_redeem_script(pubkey1: &[u8], pubkey2: &[u8]) -> Vec<u8> {
        let mut script = Vec::new();
        script.push(0x52); // OP_2
        script.push(pubkey1.len() as u8);
        script.extend_from_slice(pubkey1);
        script.push(pubkey2.len() as u8);
        script.extend_from_slice(pubkey2);
        script.push(0x52); // OP_2
        script.push(0xae); // OP_CHECKMULTISIG
        script
    }

    /// Create a 2-of-3 multisig redeem script
    pub fn create_2of3_redeem_script(pubkey1: &[u8], pubkey2: &[u8], pubkey3: &[u8]) -> Vec<u8> {
        let mut script = Vec::new();
        script.push(0x52); // OP_2
        script.push(pubkey1.len() as u8);
        script.extend_from_slice(pubkey1);
        script.push(pubkey2.len() as u8);
        script.extend_from_slice(pubkey2);
        script.push(pubkey3.len() as u8);
        script.extend_from_slice(pubkey3);
        script.push(0x53); // OP_3
        script.push(0xae); // OP_CHECKMULTISIG
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
        script.push(0x50 + m); // OP_m

        for pubkey in pubkeys {
            script.push(pubkey.len() as u8);
            script.extend_from_slice(pubkey);
        }

        script.push(0x50 + pubkeys.len() as u8); // OP_n
        script.push(0xae); // OP_CHECKMULTISIG

        Ok(script)
    }

    /// Get the witness script hash (for creating P2WSH output)
    pub fn get_witness_script_hash(&self) -> Vec<u8> {
        sha256(&self.redeem_script).to_vec()
    }

    pub fn add_input(&mut self, txid: [u8; 32], vout: u32, amount: u64) {
        self.inputs.push(P2WSHTxInput {
            txid,
            vout,
            sequence: Sequence::enable_locktime(),
            sighash_flag: SighashFlag::All,
            amount,
        });
    }

    pub fn add_output(&mut self, amount: u64, script_pubkey: Vec<u8>) {
        self.outputs.push(P2WSHTxOutput {
            amount,
            script_pubkey,
        });
    }

    pub fn get_redeem_script(&self) -> &[u8] {
        &self.redeem_script
    }

    /// Build unsigned transaction
    pub fn build_unsigned(&self) -> Vec<u8> {
        let mut tx = Vec::new();

        tx.extend_from_slice(&self.version.to_le_bytes());
        tx.extend_from_slice(&varint_len(&vec![0u8; self.inputs.len()]));

        for input in &self.inputs {
            let mut txid_le = input.txid;
            txid_le.reverse();
            tx.extend_from_slice(&txid_le);
            tx.extend_from_slice(&input.vout.to_le_bytes());
            tx.push(0x00); // Empty scriptSig
            tx.extend_from_slice(&input.sequence.to_bytes());
        }

        tx.extend_from_slice(&varint_len(&vec![0u8; self.outputs.len()]));

        for output in &self.outputs {
            tx.extend_from_slice(&output.amount.to_le_bytes());
            tx.extend_from_slice(&varint_len(&output.script_pubkey));
            tx.extend_from_slice(&output.script_pubkey);
        }

        tx.extend_from_slice(&self.locktime.to_bytes());

        tx
    }

    /// Sign the P2WSH multisig transaction with custom sighash flags per input
    pub fn sign(
        &self,
        privkeys_per_input: &[Vec<[u8; 32]>], // Vector of privkey sets, one per input
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if privkeys_per_input.len() != self.inputs.len() {
            return Err("Number of privkey sets must match number of inputs".into());
        }

        let mut witnesses = Vec::new();

        for (i, (privkeys, input)) in privkeys_per_input
            .iter()
            .zip(self.inputs.iter())
            .enumerate()
        {
            // Convert to sighash format
            let sighash_inputs: Vec<SighashInput> = self
                .inputs
                .iter()
                .map(|inp| SighashInput {
                    txid: inp.txid,
                    vout: inp.vout,
                    script_pubkey: self.redeem_script.clone(),
                    amount: inp.amount,
                    sequence: inp.sequence.to_u32(),
                })
                .collect();

            let sighash_outputs: Vec<SighashOutput> = self
                .outputs
                .iter()
                .map(|out| SighashOutput {
                    amount: out.amount,
                    script_pubkey: out.script_pubkey.clone(),
                })
                .collect();

            // Compute sighash with custom flag
            let sighash = SegwitV0Sighash::compute(
                self.version,
                &sighash_inputs,
                &sighash_outputs,
                i,
                input.sighash_flag,
                self.locktime.to_u32(),
            )?;

            // Create signatures for each private key
            let mut signatures = Vec::new();
            for privkey in privkeys {
                let mut signature = sign_hash(privkey, &sighash)?;

                // Append sighash flag if not ALL
                if input.sighash_flag != SighashFlag::All {
                    signature.push(input.sighash_flag.to_u8());
                } else {
                    signature.push(0x01);
                }

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

            witnesses.push(witness);
        }

        // Build final signed transaction
        let mut signed_tx = Vec::new();

        signed_tx.extend_from_slice(&self.version.to_le_bytes());
        signed_tx.push(0x00); // marker
        signed_tx.push(0x01); // flag

        signed_tx.extend_from_slice(&varint_len(&vec![0u8; self.inputs.len()]));

        for input in &self.inputs {
            let mut txid_le = input.txid;
            txid_le.reverse();
            signed_tx.extend_from_slice(&txid_le);
            signed_tx.extend_from_slice(&input.vout.to_le_bytes());
            signed_tx.push(0x00); // Empty scriptSig
            signed_tx.extend_from_slice(&input.sequence.to_bytes());
        }

        signed_tx.extend_from_slice(&varint_len(&vec![0u8; self.outputs.len()]));

        for output in &self.outputs {
            signed_tx.extend_from_slice(&output.amount.to_le_bytes());
            signed_tx.extend_from_slice(&varint_len(&output.script_pubkey));
            signed_tx.extend_from_slice(&output.script_pubkey);
        }

        // Witnesses
        for witness in &witnesses {
            signed_tx.extend_from_slice(witness);
        }

        signed_tx.extend_from_slice(&self.locktime.to_bytes());

        Ok(signed_tx)
    }
}

// Implement SighashFlagSupport trait
impl SighashFlagSupport for P2WSHMultisigTransaction {
    fn get_sighash_flag(&self, input_index: usize) -> Option<SighashFlag> {
        self.inputs.get(input_index).map(|i| i.sighash_flag)
    }

    fn set_sighash_flag(&mut self, input_index: usize, flag: SighashFlag) -> Result<(), String> {
        if input_index >= self.inputs.len() {
            return Err("Input index out of bounds".to_string());
        }

        if !flag.is_valid_for_segwit() {
            return Err(format!("Invalid sighash flag for SegWit: {:?}", flag));
        }

        self.inputs[input_index].sighash_flag = flag;
        Ok(())
    }

    fn get_all_sighash_flags(&self) -> Vec<SighashFlag> {
        self.inputs.iter().map(|i| i.sighash_flag).collect()
    }
}

// Implement AbsoluteTimelockSupport trait
impl AbsoluteTimelockSupport for P2WSHMultisigTransaction {
    fn get_locktime(&self) -> LockTime {
        self.locktime
    }

    fn set_locktime(&mut self, locktime: LockTime) {
        self.locktime = locktime;
    }

    fn is_locktime_enabled(&self) -> bool {
        if !self.locktime.is_enabled() {
            return false;
        }

        !self.inputs.iter().all(|i| i.sequence.disables_locktime())
    }

    fn is_final_at(&self, block_height: u32, block_time: u32) -> bool {
        if matches!(self.locktime, LockTime::None) {
            return true;
        }

        if self.inputs.iter().all(|i| i.sequence.disables_locktime()) {
            return true;
        }

        match self.locktime {
            LockTime::BlockHeight(h) => block_height >= h,
            LockTime::Timestamp(t) => block_time >= t,
            LockTime::None => true,
        }
    }
}

// Implement RelativeTimelockSupport trait
impl RelativeTimelockSupport for P2WSHMultisigTransaction {
    fn get_sequence(&self, input_index: usize) -> Option<Sequence> {
        self.inputs.get(input_index).map(|i| i.sequence)
    }

    fn set_sequence(&mut self, input_index: usize, sequence: Sequence) -> Result<(), String> {
        if input_index >= self.inputs.len() {
            return Err("Input index out of bounds".to_string());
        }

        self.inputs[input_index].sequence = sequence;
        Ok(())
    }

    fn get_all_sequences(&self) -> Vec<Sequence> {
        self.inputs.iter().map(|i| i.sequence).collect()
    }
}

// Implement combined TimelockSupport trait
impl TimelockSupport for P2WSHMultisigTransaction {}

// Implement OpCLTVSupport trait
impl OpCLTVSupport for P2WSHMultisigTransaction {
    fn can_satisfy_cltv(&self, input_index: usize, script_locktime: LockTime) -> bool {
        if let Some(sequence) = self.get_sequence(input_index) {
            OpCheckLockTimeVerify::verify(script_locktime, self.locktime, sequence)
        } else {
            false
        }
    }

    fn get_max_cltv_locktime(&self, _input_index: usize) -> Option<LockTime> {
        if self.is_locktime_enabled() {
            Some(self.locktime)
        } else {
            None
        }
    }
}

// Implement OpCSVSupport trait
impl OpCSVSupport for P2WSHMultisigTransaction {
    fn can_satisfy_csv(&self, input_index: usize, script_sequence: Sequence) -> bool {
        if let Some(tx_sequence) = self.get_sequence(input_index) {
            OpCheckSequenceVerify::verify(script_sequence, tx_sequence)
        } else {
            false
        }
    }

    fn get_max_csv_sequence(&self, input_index: usize) -> Option<Sequence> {
        self.get_sequence(input_index)
            .filter(|s| s.is_relative_locktime_enabled())
    }
}

// Implement TimelockTransactionBuilder trait
impl TimelockTransactionBuilder for P2WSHMultisigTransaction {
    fn with_absolute_locktime(locktime: LockTime) -> Self {
        Self {
            version: 2,
            inputs: Vec::new(),
            outputs: Vec::new(),
            locktime,
            redeem_script: Vec::new(),
        }
    }

    fn with_relative_locktimes(sequences: Vec<Sequence>) -> Self {
        let mut tx = Self::new(Vec::new());
        for seq in sequences {
            tx.inputs.push(P2WSHTxInput {
                txid: [0u8; 32],
                vout: 0,
                sequence: seq,
                sighash_flag: SighashFlag::All,
                amount: 0,
            });
        }
        tx
    }

    fn add_input_with_sequence(&mut self, txid: [u8; 32], vout: u32, sequence: Sequence) {
        self.inputs.push(P2WSHTxInput {
            txid,
            vout,
            sequence,
            sighash_flag: SighashFlag::All,
            amount: 0,
        });
    }

    fn add_cltv_input(&mut self, txid: [u8; 32], vout: u32, script_locktime: LockTime) {
        if self.locktime.to_u32() < script_locktime.to_u32() {
            self.locktime = script_locktime;
        }

        self.inputs.push(P2WSHTxInput {
            txid,
            vout,
            sequence: Sequence::enable_locktime(),
            sighash_flag: SighashFlag::All,
            amount: 0,
        });
    }

    fn add_csv_input(&mut self, txid: [u8; 32], vout: u32, script_sequence: Sequence) {
        self.inputs.push(P2WSHTxInput {
            txid,
            vout,
            sequence: script_sequence,
            sighash_flag: SighashFlag::All,
            amount: 0,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p2wsh_with_different_sighash_flags() {
        let privkey1 = [0x11u8; 32];
        let privkey2 = [0x22u8; 32];

        let pubkey1 = privkey_to_pubkey(&privkey1).unwrap();
        let pubkey2 = privkey_to_pubkey(&privkey2).unwrap();

        let redeem_script = P2WSHMultisigTransaction::create_2of2_redeem_script(&pubkey1, &pubkey2);

        let mut tx = P2WSHMultisigTransaction::new(redeem_script);

        // Add two inputs with different sighash flags
        tx.add_input([0x42; 32], 0, 100_000_000);
        tx.add_input([0x43; 32], 0, 200_000_000);

        tx.set_sighash_flag(0, SighashFlag::All).unwrap();
        tx.set_sighash_flag(1, SighashFlag::AllAnyoneCanPay)
            .unwrap();

        tx.add_output(140_000_000, vec![0x00, 0x20]);
        tx.add_output(150_000_000, vec![0x00, 0x20]);

        // Verify flags are set correctly
        assert_eq!(tx.get_sighash_flag(0), Some(SighashFlag::All));
        assert_eq!(tx.get_sighash_flag(1), Some(SighashFlag::AllAnyoneCanPay));
        assert!(tx.has_anyonecanpay(1));
    }

    #[test]
    fn test_p2wsh_multisig_with_csv() {
        let privkey1 = [0x11u8; 32];
        let privkey2 = [0x22u8; 32];

        let pubkey1 = privkey_to_pubkey(&privkey1).unwrap();
        let pubkey2 = privkey_to_pubkey(&privkey2).unwrap();

        let redeem_script = P2WSHMultisigTransaction::create_2of2_redeem_script(&pubkey1, &pubkey2);

        let mut tx = P2WSHMultisigTransaction::new(redeem_script);

        tx.add_input([0x42; 32], 0, 100_000_000);
        tx.set_sequence(0, Sequence::from_blocks(144)).unwrap();

        tx.add_output(99_000_000, vec![0x00, 0x20]);

        assert!(tx.is_relative_locktime_enabled(0));
        assert_eq!(tx.get_sequence_locktime_value(0), Some(144));

        // Check CSV compatibility
        let script_seq = Sequence::from_blocks(100);
        assert!(tx.can_satisfy_csv(0, script_seq));
    }

    #[test]
    fn test_witness_script_hash() {
        let privkey1 = [0x11u8; 32];
        let privkey2 = [0x22u8; 32];

        let pubkey1 = privkey_to_pubkey(&privkey1).unwrap();
        let pubkey2 = privkey_to_pubkey(&privkey2).unwrap();

        let redeem_script = P2WSHMultisigTransaction::create_2of2_redeem_script(&pubkey1, &pubkey2);

        let tx = P2WSHMultisigTransaction::new(redeem_script);
        let witness_hash = tx.get_witness_script_hash();

        assert_eq!(witness_hash.len(), 32);
    }
}
