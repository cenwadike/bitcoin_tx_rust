//! Legacy P2PKH Transaction with Trait Support
//!
//! This implements the original Bitcoin transaction type with full trait support

use crate::sighash::{LegacySighash, SighashFlag, SighashInput, SighashOutput};
use crate::timelocks::{LockTime, OpCheckLockTimeVerify, OpCheckSequenceVerify, Sequence};
use crate::transaction::*;
use crate::utils::*;

/// Legacy P2PKH Transaction with full trait support
#[derive(Debug, Clone)]
pub struct P2PKHTransaction {
    version: u32,
    inputs: Vec<LegacyTxInput>,
    outputs: Vec<LegacyTxOutput>,
    locktime: LockTime,
}

#[derive(Debug, Clone)]
pub struct LegacyTxInput {
    pub txid: [u8; 32],
    pub vout: u32,
    pub sequence: Sequence,
    pub sighash_flag: SighashFlag,
    pub script_pubkey: Vec<u8>,
    pub amount: u64,
}

#[derive(Debug, Clone)]
pub struct LegacyTxOutput {
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
}

impl P2PKHTransaction {
    pub fn new() -> Self {
        Self {
            version: 1, // Version 1 for legacy
            inputs: Vec::new(),
            outputs: Vec::new(),
            locktime: LockTime::None,
        }
    }

    pub fn add_input(&mut self, txid: [u8; 32], vout: u32, script_pubkey: Vec<u8>, amount: u64) {
        self.inputs.push(LegacyTxInput {
            txid,
            vout,
            sequence: Sequence::max(), // Default: 0xffffffff
            sighash_flag: SighashFlag::All,
            script_pubkey,
            amount,
        });
    }

    pub fn add_output(&mut self, amount: u64, script_pubkey: Vec<u8>) {
        self.outputs.push(LegacyTxOutput {
            amount,
            script_pubkey,
        });
    }

    /// Create P2PKH scriptPubKey from public key
    pub fn create_p2pkh_script(pubkey: &[u8]) -> Vec<u8> {
        let pk_hash = hash160(pubkey);
        let mut script = vec![0x76, 0xa9, 0x14]; // OP_DUP OP_HASH160 <20 bytes>
        script.extend_from_slice(&pk_hash);
        script.extend_from_slice(&[0x88, 0xac]); // OP_EQUALVERIFY OP_CHECKSIG
        script
    }

    /// Build unsigned transaction (for inspection/debugging)
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

    /// Sign the transaction using the configured sighash flags
    pub fn sign(&self, privkeys: &[[u8; 32]]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if privkeys.len() != self.inputs.len() {
            return Err("Number of private keys must match number of inputs".into());
        }

        let mut script_sigs = Vec::new();

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
            let sighash = LegacySighash::compute(
                self.version,
                &sighash_inputs,
                &sighash_outputs,
                i,
                input.sighash_flag,
                self.locktime.to_u32(),
            )?;

            // Sign
            let mut signature = sign_hash(privkey, &sighash)?;
            signature.push(input.sighash_flag.to_u8());

            // Create pubkey
            let pubkey = privkey_to_pubkey(privkey)?;

            // Build scriptSig
            let mut script_sig = Vec::new();
            script_sig.extend_from_slice(&pushbytes(&signature));
            script_sig.extend_from_slice(&pushbytes(&pubkey));

            script_sigs.push(script_sig);
        }

        // Build final signed transaction
        let mut signed_tx = Vec::new();

        signed_tx.extend_from_slice(&self.version.to_le_bytes());
        signed_tx.extend_from_slice(&varint_len(&vec![0u8; self.inputs.len()]));

        for (i, input) in self.inputs.iter().enumerate() {
            let mut txid_le = input.txid;
            txid_le.reverse();
            signed_tx.extend_from_slice(&txid_le);
            signed_tx.extend_from_slice(&input.vout.to_le_bytes());

            // Add scriptSig
            signed_tx.extend_from_slice(&varint_len(&script_sigs[i]));
            signed_tx.extend_from_slice(&script_sigs[i]);

            signed_tx.extend_from_slice(&input.sequence.to_bytes());
        }

        signed_tx.extend_from_slice(&varint_len(&vec![0u8; self.outputs.len()]));

        for output in &self.outputs {
            signed_tx.extend_from_slice(&output.amount.to_le_bytes());
            signed_tx.extend_from_slice(&varint_len(&output.script_pubkey));
            signed_tx.extend_from_slice(&output.script_pubkey);
        }

        signed_tx.extend_from_slice(&self.locktime.to_bytes());

        Ok(signed_tx)
    }
}

// Implement SighashFlagSupport trait
impl SighashFlagSupport for P2PKHTransaction {
    fn get_sighash_flag(&self, input_index: usize) -> Option<SighashFlag> {
        self.inputs.get(input_index).map(|i| i.sighash_flag)
    }

    fn set_sighash_flag(&mut self, input_index: usize, flag: SighashFlag) -> Result<(), String> {
        if input_index >= self.inputs.len() {
            return Err("Input index out of bounds".to_string());
        }

        if !flag.is_valid_for_legacy() {
            return Err(format!("Invalid sighash flag for legacy: {:?}", flag));
        }

        self.inputs[input_index].sighash_flag = flag;
        Ok(())
    }

    fn get_all_sighash_flags(&self) -> Vec<SighashFlag> {
        self.inputs.iter().map(|i| i.sighash_flag).collect()
    }
}

// Implement AbsoluteTimelockSupport trait
impl AbsoluteTimelockSupport for P2PKHTransaction {
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
impl RelativeTimelockSupport for P2PKHTransaction {
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
impl TimelockSupport for P2PKHTransaction {}

// Implement OpCLTVSupport trait
impl OpCLTVSupport for P2PKHTransaction {
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
impl OpCSVSupport for P2PKHTransaction {
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
impl TimelockTransactionBuilder for P2PKHTransaction {
    fn with_absolute_locktime(locktime: LockTime) -> Self {
        Self {
            version: 1,
            inputs: Vec::new(),
            outputs: Vec::new(),
            locktime,
        }
    }

    fn with_relative_locktimes(sequences: Vec<Sequence>) -> Self {
        let mut tx = Self::new();
        for seq in sequences {
            tx.inputs.push(LegacyTxInput {
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
        self.inputs.push(LegacyTxInput {
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

        self.inputs.push(LegacyTxInput {
            txid,
            vout,
            sequence: Sequence::enable_locktime(),
            sighash_flag: SighashFlag::All,
            script_pubkey: Vec::new(),
            amount: 0,
        });
    }

    fn add_csv_input(&mut self, txid: [u8; 32], vout: u32, script_sequence: Sequence) {
        self.inputs.push(LegacyTxInput {
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
    fn test_legacy_sighash_flags() {
        let mut tx = P2PKHTransaction::new();
        tx.add_input([0x42; 32], 0, vec![0x76, 0xa9, 0x14], 100_000_000);

        // Test setting different flags
        tx.set_sighash_flag(0, SighashFlag::Single).unwrap();
        assert_eq!(tx.get_sighash_flag(0), Some(SighashFlag::Single));

        // Test that DEFAULT flag is invalid for legacy
        assert!(tx.set_sighash_flag(0, SighashFlag::Default).is_err());
    }

    #[test]
    fn test_legacy_signing() {
        let privkey = [0x11u8; 32];
        let pubkey = privkey_to_pubkey(&privkey).unwrap();

        let mut tx = P2PKHTransaction::new();
        let script_pubkey = P2PKHTransaction::create_p2pkh_script(&pubkey);

        tx.add_input([0x42; 32], 0, script_pubkey, 100_000_000);
        tx.add_output(99_000_000, vec![0x76, 0xa9, 0x14]);

        let signed = tx.sign(&[privkey]).unwrap();
        assert!(!signed.is_empty());

        // Verify no segwit marker (legacy transactions don't have 0x00 0x01)
        assert_ne!(&signed[4..6], &[0x00, 0x01]);
    }

    #[test]
    fn test_legacy_with_locktime() {
        let mut tx = P2PKHTransaction::with_absolute_locktime(LockTime::BlockHeight(500000));

        tx.add_input([0x42; 32], 0, vec![0x76, 0xa9, 0x14], 100_000_000);
        tx.set_sequence(0, Sequence::enable_locktime()).unwrap();

        assert!(tx.is_locktime_enabled());
        assert!(!tx.is_final_at(499999, 0));
        assert!(tx.is_final_at(500000, 0));
    }
}
