//! Multi-Input P2WPKH Transaction with Trait Support

use crate::sighash::{SegwitV0Sighash, SighashFlag, SighashInput, SighashOutput};
use crate::timelocks::{LockTime, OpCheckLockTimeVerify, OpCheckSequenceVerify, Sequence};
use crate::transaction::*;
use crate::utils::*;

/// Multi-Input P2WPKH Transaction with full trait support
#[derive(Debug, Clone)]
pub struct MultiInputP2WPKHTransaction {
    version: u32,
    inputs: Vec<MultiInputP2WPKHTxInput>,
    outputs: Vec<MultiInputP2WPKHTxOutput>,
    locktime: LockTime,
}

#[derive(Debug, Clone)]
pub struct MultiInputP2WPKHTxInput {
    pub txid: [u8; 32],
    pub vout: u32,
    pub sequence: Sequence,
    pub sighash_flag: SighashFlag,
    pub script_pubkey: Vec<u8>,
    pub amount: u64,
}

#[derive(Debug, Clone)]
pub struct MultiInputP2WPKHTxOutput {
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
}

impl MultiInputP2WPKHTransaction {
    pub fn new() -> Self {
        Self {
            version: 2,
            inputs: Vec::new(),
            outputs: Vec::new(),
            locktime: LockTime::None,
        }
    }

    pub fn add_input(&mut self, txid: [u8; 32], vout: u32, script_pubkey: Vec<u8>, amount: u64) {
        self.inputs.push(MultiInputP2WPKHTxInput {
            txid,
            vout,
            sequence: Sequence::enable_locktime(),
            sighash_flag: SighashFlag::All,
            script_pubkey,
            amount,
        });
    }

    pub fn add_output(&mut self, amount: u64, script_pubkey: Vec<u8>) {
        self.outputs.push(MultiInputP2WPKHTxOutput {
            amount,
            script_pubkey,
        });
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

    /// Sign the transaction with custom sighash flags per input
    pub fn sign(&self, privkeys: &[[u8; 32]]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if privkeys.len() != self.inputs.len() {
            return Err("Number of private keys must match number of inputs".into());
        }

        let mut witnesses = Vec::new();

        for (i, (privkey, input)) in privkeys.iter().zip(self.inputs.iter()).enumerate() {
            // Convert to sighash format
            let sighash_inputs: Vec<SighashInput> = self
                .inputs
                .iter()
                .map(|inp| SighashInput {
                    txid: inp.txid,
                    vout: inp.vout,
                    script_pubkey: inp.script_pubkey.clone(),
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

            // Sign
            let mut signature = sign_hash(privkey, &sighash)?;

            // Append sighash flag
            if input.sighash_flag != SighashFlag::All {
                signature.push(input.sighash_flag.to_u8());
            } else {
                signature.push(0x01);
            }

            // Create pubkey
            let pubkey = privkey_to_pubkey(privkey)?;

            // Build witness
            let mut witness = Vec::new();
            witness.push(0x02); // 2 items
            witness.extend_from_slice(&pushbytes(&signature));
            witness.extend_from_slice(&pushbytes(&pubkey));

            witnesses.push(witness);
        }

        // Build final transaction
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
            signed_tx.push(0x00); // empty scriptSig
            signed_tx.extend_from_slice(&input.sequence.to_bytes());
        }

        signed_tx.extend_from_slice(&varint_len(&vec![0u8; self.outputs.len()]));

        for output in &self.outputs {
            signed_tx.extend_from_slice(&output.amount.to_le_bytes());
            signed_tx.extend_from_slice(&varint_len(&output.script_pubkey));
            signed_tx.extend_from_slice(&output.script_pubkey);
        }

        for witness in &witnesses {
            signed_tx.extend_from_slice(witness);
        }

        signed_tx.extend_from_slice(&self.locktime.to_bytes());

        Ok(signed_tx)
    }
}

// Implement all traits (same pattern as P2WPKH)
impl SighashFlagSupport for MultiInputP2WPKHTransaction {
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

impl AbsoluteTimelockSupport for MultiInputP2WPKHTransaction {
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

impl RelativeTimelockSupport for MultiInputP2WPKHTransaction {
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

impl TimelockSupport for MultiInputP2WPKHTransaction {}

impl OpCLTVSupport for MultiInputP2WPKHTransaction {
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

impl OpCSVSupport for MultiInputP2WPKHTransaction {
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

impl TimelockTransactionBuilder for MultiInputP2WPKHTransaction {
    fn with_absolute_locktime(locktime: LockTime) -> Self {
        Self {
            version: 2,
            inputs: Vec::new(),
            outputs: Vec::new(),
            locktime,
        }
    }

    fn with_relative_locktimes(sequences: Vec<Sequence>) -> Self {
        let mut tx = Self::new();
        for seq in sequences {
            tx.inputs.push(MultiInputP2WPKHTxInput {
                txid: [0u8; 32],
                vout: 0,
                sequence: seq,
                sighash_flag: SighashFlag::All,
                script_pubkey: Vec::new(),
                amount: 0,
            });
        }
        tx
    }

    fn add_input_with_sequence(&mut self, txid: [u8; 32], vout: u32, sequence: Sequence) {
        self.inputs.push(MultiInputP2WPKHTxInput {
            txid,
            vout,
            sequence,
            sighash_flag: SighashFlag::All,
            script_pubkey: Vec::new(),
            amount: 0,
        });
    }

    fn add_cltv_input(&mut self, txid: [u8; 32], vout: u32, script_locktime: LockTime) {
        if self.locktime.to_u32() < script_locktime.to_u32() {
            self.locktime = script_locktime;
        }

        self.inputs.push(MultiInputP2WPKHTxInput {
            txid,
            vout,
            sequence: Sequence::enable_locktime(),
            sighash_flag: SighashFlag::All,
            script_pubkey: Vec::new(),
            amount: 0,
        });
    }

    fn add_csv_input(&mut self, txid: [u8; 32], vout: u32, script_sequence: Sequence) {
        self.inputs.push(MultiInputP2WPKHTxInput {
            txid,
            vout,
            sequence: script_sequence,
            sighash_flag: SighashFlag::All,
            script_pubkey: Vec::new(),
            amount: 0,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multi_input_with_different_sighash_flags() {
        let mut tx = MultiInputP2WPKHTransaction::new();

        tx.add_input([0x42; 32], 0, vec![0x00, 0x14], 100_000_000);
        tx.add_input([0x43; 32], 0, vec![0x00, 0x14], 200_000_000);

        // Set different sighash flags
        tx.set_sighash_flag(0, SighashFlag::All).unwrap();
        tx.set_sighash_flag(1, SighashFlag::AllAnyoneCanPay)
            .unwrap();

        tx.add_output(140_000_000, vec![0x00, 0x14]);
        tx.add_output(150_000_000, vec![0x00, 0x14]);

        assert_eq!(tx.get_sighash_flag(0), Some(SighashFlag::All));
        assert_eq!(tx.get_sighash_flag(1), Some(SighashFlag::AllAnyoneCanPay));
        assert!(tx.has_anyonecanpay(1));
    }

    #[test]
    fn test_multi_input_with_mixed_timelocks() {
        let mut tx =
            MultiInputP2WPKHTransaction::with_absolute_locktime(LockTime::BlockHeight(700000));

        tx.add_input([0x42; 32], 0, vec![0x00, 0x14], 100_000_000);
        tx.add_input([0x43; 32], 0, vec![0x00, 0x14], 100_000_000);

        tx.set_sequence(0, Sequence::from_blocks(144)).unwrap();
        tx.set_sequence(1, Sequence::from_time_intervals(10))
            .unwrap();

        tx.add_output(190_000_000, vec![0x00, 0x14]);

        assert!(tx.is_relative_locktime_enabled(0));
        assert!(tx.is_time_based_sequence(1));
        assert!(tx.has_any_timelock());
    }
}
