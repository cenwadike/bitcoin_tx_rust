//! Taproot P2TR Transaction with Trait Support
//!
//! This implements Taproot (P2TR) transactions with full trait support for
//! both key-path and script-path spending

use crate::crypto::varint_encode;
use crate::schnorr::{schnorr_pubkey_gen, schnorr_sign, taproot_tweak_privkey};
use crate::sighash::{SighashFlag, SighashInput, SighashOutput, TaprootSighash};
use crate::taptree::{TapLeaf, compute_control_block};
use crate::timelocks::{LockTime, OpCheckLockTimeVerify, OpCheckSequenceVerify, Sequence};
use crate::transaction::*;
use crate::utils::*;

// Spend Path Enum for Taproot
#[derive(Debug, Clone)]
pub enum SpendPath {
    KeyPath {
        internal_privkey: [u8; 32],
        merkle_root: Option<[u8; 32]>,
    },
    ScriptPath {
        internal_privkey: [u8; 32], // key that signs the tapscript
        leaf: TapLeaf,
        merkle_path: Vec<[u8; 32]>, // proof from leaf to root
        output_key_parity: bool,    // tweaked output key parity
    },
}

/// Taproot Transaction with full trait support
#[derive(Debug, Clone)]
pub struct TaprootTransaction {
    version: u32,
    inputs: Vec<TaprootTxInput>,
    outputs: Vec<TaprootTxOutput>,
    locktime: LockTime,
}

#[derive(Debug, Clone)]
pub struct TaprootTxInput {
    pub txid: [u8; 32],
    pub vout: u32,
    pub sequence: Sequence,
    pub sighash_flag: SighashFlag,
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
    pub spend_path: Option<SpendPath>,
}

#[derive(Debug, Clone)]
pub struct TaprootTxOutput {
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
}

impl TaprootTransaction {
    pub fn new() -> Self {
        Self {
            version: 2,
            inputs: Vec::new(),
            outputs: Vec::new(),
            locktime: LockTime::None,
        }
    }

    pub fn add_input(&mut self, txid: [u8; 32], vout: u32, amount: u64, script_pubkey: Vec<u8>) {
        self.inputs.push(TaprootTxInput {
            txid,
            vout,
            sequence: Sequence::enable_locktime(),
            sighash_flag: SighashFlag::Default, // Taproot default
            amount,
            script_pubkey,
            spend_path: None,
        });
    }

    pub fn add_output(&mut self, amount: u64, script_pubkey: Vec<u8>) {
        self.outputs.push(TaprootTxOutput {
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

    /// Sign the transaction — supports mixed key-path & script-path per input
    pub fn sign(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if self.inputs.is_empty() {
            return Err("Transaction must have inputs".into());
        }

        let mut witnesses = Vec::new();

        let sighash_inputs: Vec<SighashInput> = self
            .inputs
            .iter()
            .map(|i| SighashInput {
                txid: i.txid,
                vout: i.vout,
                script_pubkey: i.script_pubkey.clone(),
                amount: i.amount,
                sequence: i.sequence.to_u32(),
            })
            .collect();

        let sighash_outputs: Vec<SighashOutput> = self
            .outputs
            .iter()
            .map(|o| SighashOutput {
                amount: o.amount,
                script_pubkey: o.script_pubkey.clone(),
            })
            .collect();

        for (idx, input) in self.inputs.iter().enumerate() {
            let path = input
                .spend_path
                .as_ref()
                .ok_or("Spend path not set for input")?;

            let sighash = TaprootSighash::compute(
                self.version,
                &sighash_inputs,
                &sighash_outputs,
                idx,
                input.sighash_flag,
                self.locktime.to_u32(),
                false,
            )?;

            let witness_items: Vec<Vec<u8>> = match path {
                SpendPath::KeyPath {
                    internal_privkey,
                    merkle_root,
                } => {
                    let tweaked = taproot_tweak_privkey(internal_privkey, merkle_root.as_ref())?;
                    let mut sig = schnorr_sign(&tweaked, &sighash)?;
                    if input.sighash_flag != SighashFlag::Default {
                        sig.push(input.sighash_flag as u8);
                    }
                    vec![sig]
                }

                SpendPath::ScriptPath {
                    internal_privkey,
                    leaf,
                    merkle_path,
                    output_key_parity,
                } => {
                    let mut sig = schnorr_sign(internal_privkey, &sighash)?;
                    if input.sighash_flag != SighashFlag::Default {
                        sig.push(input.sighash_flag as u8);
                    }

                    let internal_pubkey = schnorr_pubkey_gen(internal_privkey)?;

                    let control_block = compute_control_block(
                        &internal_pubkey,
                        merkle_path,
                        *output_key_parity,
                        leaf.version,
                    );

                    vec![sig, leaf.script.clone(), control_block]
                }
            };

            // Correct witness serialization
            let mut witness_ser = vec![];
            witness_ser.extend_from_slice(&varint_encode(witness_items.len() as u64));
            for item in witness_items {
                witness_ser.extend_from_slice(&varint_encode(item.len() as u64));
                witness_ser.extend_from_slice(&item);
            }
            witnesses.push(witness_ser);
        }

        // Build signed transaction
        let mut tx = Vec::new();
        tx.extend_from_slice(&self.version.to_le_bytes());
        tx.push(0x00); // marker
        tx.push(0x01); // flag

        tx.extend_from_slice(&varint_encode(self.inputs.len() as u64));
        for input in &self.inputs {
            let mut txid = input.txid;
            txid.reverse();
            tx.extend_from_slice(&txid);
            tx.extend_from_slice(&input.vout.to_le_bytes());
            tx.push(0x00);
            tx.extend_from_slice(&input.sequence.to_bytes());
        }

        tx.extend_from_slice(&varint_encode(self.outputs.len() as u64));
        for output in &self.outputs {
            tx.extend_from_slice(&output.amount.to_le_bytes());
            tx.extend_from_slice(&varint_encode(output.script_pubkey.len() as u64));
            tx.extend_from_slice(&output.script_pubkey);
        }

        for witness in witnesses {
            tx.extend_from_slice(&witness);
        }

        tx.extend_from_slice(&self.locktime.to_bytes());

        Ok(tx)
    }

    /// Set key-path spending for a specific input
    pub fn set_keypath_spend(
        &mut self,
        input_index: usize,
        internal_privkey: [u8; 32],
        merkle_root: Option<[u8; 32]>,
    ) -> Result<(), &'static str> {
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or("Invalid input index")?;
        input.spend_path = Some(SpendPath::KeyPath {
            internal_privkey,
            merkle_root,
        });
        Ok(())
    }

    /// Set script-path spending for a specific input
    pub fn set_scriptpath_spend(
        &mut self,
        input_index: usize,
        internal_privkey: [u8; 32],
        leaf: TapLeaf,
        merkle_path: Vec<[u8; 32]>,
        output_key_parity: bool,
    ) -> Result<(), &'static str> {
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or("Invalid input index")?;
        input.spend_path = Some(SpendPath::ScriptPath {
            internal_privkey,
            leaf,
            merkle_path,
            output_key_parity,
        });
        Ok(())
    }
}

// Implement SighashFlagSupport trait
impl SighashFlagSupport for TaprootTransaction {
    fn get_sighash_flag(&self, input_index: usize) -> Option<SighashFlag> {
        self.inputs.get(input_index).map(|i| i.sighash_flag)
    }

    fn set_sighash_flag(&mut self, input_index: usize, flag: SighashFlag) -> Result<(), String> {
        if input_index >= self.inputs.len() {
            return Err("Input index out of bounds".to_string());
        }

        if !flag.is_valid_for_taproot() {
            return Err(format!("Invalid sighash flag for Taproot: {:?}", flag));
        }

        self.inputs[input_index].sighash_flag = flag;
        Ok(())
    }

    fn get_all_sighash_flags(&self) -> Vec<SighashFlag> {
        self.inputs.iter().map(|i| i.sighash_flag).collect()
    }
}

// Implement AbsoluteTimelockSupport trait
impl AbsoluteTimelockSupport for TaprootTransaction {
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
impl RelativeTimelockSupport for TaprootTransaction {
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
impl TimelockSupport for TaprootTransaction {}

// Implement OpCLTVSupport trait
impl OpCLTVSupport for TaprootTransaction {
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
impl OpCSVSupport for TaprootTransaction {
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
impl TimelockTransactionBuilder for TaprootTransaction {
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
            tx.inputs.push(TaprootTxInput {
                txid: [0u8; 32],
                vout: 0,
                sequence: seq,
                sighash_flag: SighashFlag::Default,
                amount: 0,
                script_pubkey: Vec::new(),
                spend_path: None,
            });
        }
        tx
    }

    fn add_input_with_sequence(&mut self, txid: [u8; 32], vout: u32, sequence: Sequence) {
        self.inputs.push(TaprootTxInput {
            txid,
            vout,
            sequence,
            sighash_flag: SighashFlag::Default,
            amount: 0,
            script_pubkey: Vec::new(),
            spend_path: None,
        });
    }

    fn add_cltv_input(&mut self, txid: [u8; 32], vout: u32, script_locktime: LockTime) {
        if self.locktime.to_u32() < script_locktime.to_u32() {
            self.locktime = script_locktime;
        }

        self.inputs.push(TaprootTxInput {
            txid,
            vout,
            sequence: Sequence::enable_locktime(),
            sighash_flag: SighashFlag::Default,
            amount: 0,
            script_pubkey: Vec::new(),
            spend_path: None,
        });
    }

    fn add_csv_input(&mut self, txid: [u8; 32], vout: u32, script_sequence: Sequence) {
        self.inputs.push(TaprootTxInput {
            txid,
            vout,
            sequence: script_sequence,
            sighash_flag: SighashFlag::Default,
            amount: 0,
            script_pubkey: Vec::new(),
            spend_path: None,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_taproot_sighash_flags() {
        let mut tx = TaprootTransaction::new();

        tx.add_input([0x42; 32], 0, 100_000_000, vec![0x51, 0x20]);
        tx.add_input([0x43; 32], 0, 200_000_000, vec![0x51, 0x20]);

        // Test DEFAULT flag (Taproot-specific)
        assert_eq!(tx.get_sighash_flag(0), Some(SighashFlag::Default));

        // Set different flags
        tx.set_sighash_flag(0, SighashFlag::All).unwrap();
        tx.set_sighash_flag(1, SighashFlag::SingleAnyoneCanPay)
            .unwrap();

        assert_eq!(tx.get_sighash_flag(0), Some(SighashFlag::All));
        assert_eq!(
            tx.get_sighash_flag(1),
            Some(SighashFlag::SingleAnyoneCanPay)
        );
        assert!(tx.has_anyonecanpay(1));
    }

    #[test]
    fn test_taproot_with_timelocks() {
        let mut tx = TaprootTransaction::with_absolute_locktime(LockTime::BlockHeight(800000));

        tx.add_input([0x42; 32], 0, 100_000_000, vec![0x51, 0x20]);
        tx.set_sequence(0, Sequence::from_blocks(144)).unwrap();

        tx.add_output(99_000_000, vec![0x51, 0x20]);

        assert!(tx.is_locktime_enabled());
        assert!(tx.is_relative_locktime_enabled(0));
        assert!(!tx.is_final_at(799999, 0));
        assert!(tx.is_final_at(800000, 0));
    }

    #[test]
    fn test_taproot_default_sighash() {
        let mut tx = TaprootTransaction::new();
        tx.add_input([0x42; 32], 0, 100_000_000, vec![0x51, 0x20]);

        // Default should be SighashFlag::Default for Taproot
        assert_eq!(tx.get_sighash_flag(0), Some(SighashFlag::Default));

        // Can change to other flags
        tx.set_sighash_flag(0, SighashFlag::All).unwrap();
        assert_eq!(tx.get_sighash_flag(0), Some(SighashFlag::All));
    }

    #[test]
    fn test_taproot_anyonecanpay() {
        let mut tx = TaprootTransaction::new();

        // Collaborative transaction: each party signs their own input
        tx.add_input([0x42; 32], 0, 50_000_000, vec![0x51, 0x20]);
        tx.add_input([0x43; 32], 0, 50_000_000, vec![0x51, 0x20]);

        // Both use ANYONECANPAY to allow independent signing
        tx.set_sighash_flag(0, SighashFlag::AllAnyoneCanPay)
            .unwrap();
        tx.set_sighash_flag(1, SighashFlag::AllAnyoneCanPay)
            .unwrap();

        tx.add_output(99_000_000, vec![0x51, 0x20]);

        assert!(tx.has_anyonecanpay(0));
        assert!(tx.has_anyonecanpay(1));
    }

    #[test]
    fn test_taproot_csv_compatibility() {
        let mut tx = TaprootTransaction::new();

        tx.add_input([0x42; 32], 0, 100_000_000, vec![0x51, 0x20]);
        tx.set_sequence(0, Sequence::from_blocks(200)).unwrap();

        tx.add_output(99_000_000, vec![0x51, 0x20]);

        // Check CSV compatibility
        let script_seq = Sequence::from_blocks(144);
        assert!(tx.can_satisfy_csv(0, script_seq));

        let too_high_seq = Sequence::from_blocks(300);
        assert!(!tx.can_satisfy_csv(0, too_high_seq));
    }
}
