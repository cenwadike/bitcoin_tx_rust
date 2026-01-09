//! Enhanced Transaction and Script-Level Timelocks
//!
//! This module implements Bitcoin's timelock mechanisms with trait support

use crate::utils::*;

/// Locktime type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockTime {
    /// Block height (0 to 499,999,999)
    BlockHeight(u32),
    /// Unix timestamp (500,000,000 and above)
    Timestamp(u32),
    /// No locktime
    None,
}

impl LockTime {
    pub fn from_u32(value: u32) -> Self {
        if value == 0 {
            LockTime::None
        } else if value < 500_000_000 {
            LockTime::BlockHeight(value)
        } else {
            LockTime::Timestamp(value)
        }
    }

    pub fn to_u32(self) -> u32 {
        match self {
            LockTime::BlockHeight(h) => h,
            LockTime::Timestamp(t) => t,
            LockTime::None => 0,
        }
    }

    pub fn to_bytes(self) -> [u8; 4] {
        self.to_u32().to_le_bytes()
    }

    /// Encode for use in script (minimal encoding)
    pub fn to_script_bytes(self) -> Vec<u8> {
        let value = self.to_u32();
        if value == 0 {
            return vec![];
        }
        if value <= 16 {
            return vec![(0x50 + value) as u8];
        }

        let mut bytes = value.to_le_bytes().to_vec();
        while bytes.len() > 1 && bytes.last() == Some(&0) {
            bytes.pop();
        }

        if let Some(&last) = bytes.last() {
            if last & 0x80 != 0 {
                bytes.push(0x00);
            }
        }

        let mut result = Vec::new();
        result.push(bytes.len() as u8);
        result.extend_from_slice(&bytes);
        result
    }

    pub fn is_enabled(self) -> bool {
        !matches!(self, LockTime::None)
    }

    /// Check if this locktime is compatible with another for comparison
    pub fn is_compatible_with(&self, other: &LockTime) -> bool {
        match (self, other) {
            (LockTime::None, _) | (_, LockTime::None) => true,
            (LockTime::BlockHeight(_), LockTime::BlockHeight(_)) => true,
            (LockTime::Timestamp(_), LockTime::Timestamp(_)) => true,
            _ => false,
        }
    }

    /// Compare two locktimes (returns None if incompatible types)
    pub fn compare(&self, other: &LockTime) -> Option<std::cmp::Ordering> {
        if !self.is_compatible_with(other) {
            return None;
        }
        Some(self.to_u32().cmp(&other.to_u32()))
    }
}

/// Sequence number for relative timelocks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sequence {
    value: u32,
}

impl Sequence {
    /// Maximum sequence (disables locktime and relative timelock)
    pub const MAX: u32 = 0xffffffff;
    /// Default sequence that enables locktime but no relative timelock
    pub const ENABLE_LOCKTIME: u32 = 0xfffffffe;
    /// Bit to enable relative timelock (BIP-68)
    pub const DISABLE_FLAG: u32 = 1 << 31;
    /// Bit to specify time-based (vs block-based) relative locktime
    pub const TYPE_FLAG: u32 = 1 << 22;
    /// Mask for the actual locktime value
    pub const LOCKTIME_MASK: u32 = 0x0000ffff;

    pub fn new(value: u32) -> Self {
        Self { value }
    }

    pub fn max() -> Self {
        Self { value: Self::MAX }
    }

    pub fn enable_locktime() -> Self {
        Self {
            value: Self::ENABLE_LOCKTIME,
        }
    }

    /// Create a relative timelock in blocks
    pub fn from_blocks(blocks: u16) -> Self {
        Self {
            value: blocks as u32,
        }
    }

    /// Create a relative timelock in 512-second intervals
    pub fn from_time_intervals(intervals: u16) -> Self {
        Self {
            value: (intervals as u32) | Self::TYPE_FLAG,
        }
    }

    pub fn is_relative_locktime_enabled(&self) -> bool {
        self.value & Self::DISABLE_FLAG == 0 && self.value != Self::MAX
    }

    pub fn is_time_based(&self) -> bool {
        self.value & Self::TYPE_FLAG != 0
    }

    pub fn locktime_value(&self) -> u16 {
        (self.value & Self::LOCKTIME_MASK) as u16
    }

    pub fn disables_locktime(&self) -> bool {
        self.value == Self::MAX
    }

    pub fn to_u32(&self) -> u32 {
        self.value
    }

    pub fn to_bytes(&self) -> [u8; 4] {
        self.value.to_le_bytes()
    }

    pub fn to_script_bytes(&self) -> Vec<u8> {
        let value = self.locktime_value();
        if value == 0 {
            return vec![];
        }
        if value <= 16 {
            return vec![(0x50 + value) as u8];
        }

        let bytes = value.to_le_bytes();
        let mut result = Vec::new();
        result.push(bytes.len() as u8);
        result.extend_from_slice(&bytes);
        result
    }

    /// Get the actual time/block count this sequence represents
    pub fn get_locktime_duration(&self) -> Option<SequenceDuration> {
        if !self.is_relative_locktime_enabled() {
            return None;
        }

        let value = self.locktime_value();
        if self.is_time_based() {
            Some(SequenceDuration::Time(value as u32 * 512)) // 512-second intervals
        } else {
            Some(SequenceDuration::Blocks(value))
        }
    }
}

/// Duration represented by a sequence
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequenceDuration {
    Blocks(u16),
    Time(u32), // in seconds
}

impl SequenceDuration {
    /// Get a human-readable description
    pub fn description(&self) -> String {
        match self {
            SequenceDuration::Blocks(n) => format!("{} blocks (~{} minutes)", n, n * 10),
            SequenceDuration::Time(s) => {
                if *s >= 3600 {
                    format!("{} hours", s / 3600)
                } else if *s >= 60 {
                    format!("{} minutes", s / 60)
                } else {
                    format!("{} seconds", s)
                }
            }
        }
    }
}

/// OP_CHECKLOCKTIMEVERIFY script builder
pub struct OpCheckLockTimeVerify;

impl OpCheckLockTimeVerify {
    /// Build a script with OP_CLTV
    pub fn build_script(locktime: LockTime, pubkey: &[u8]) -> Vec<u8> {
        let mut script = Vec::new();
        script.extend_from_slice(&locktime.to_script_bytes());
        script.push(0xb1); // OP_CHECKLOCKTIMEVERIFY
        script.push(0x75); // OP_DROP
        script.extend_from_slice(&pushbytes(pubkey));
        script.push(0xac); // OP_CHECKSIG
        script
    }

    /// Verify locktime constraints
    pub fn verify(script_locktime: LockTime, tx_locktime: LockTime, tx_sequence: Sequence) -> bool {
        if tx_sequence.disables_locktime() {
            return false;
        }

        let script_val = script_locktime.to_u32();
        let tx_val = tx_locktime.to_u32();

        if (script_val < 500_000_000) != (tx_val < 500_000_000) {
            return false;
        }

        tx_val >= script_val
    }
}

/// OP_CHECKSEQUENCEVERIFY script builder
pub struct OpCheckSequenceVerify;

impl OpCheckSequenceVerify {
    /// Build a script with OP_CSV
    pub fn build_script(sequence: Sequence, pubkey: &[u8]) -> Vec<u8> {
        let mut script = Vec::new();
        script.extend_from_slice(&sequence.to_script_bytes());
        script.push(0xb2); // OP_CHECKSEQUENCEVERIFY
        script.push(0x75); // OP_DROP
        script.extend_from_slice(&pushbytes(pubkey));
        script.push(0xac); // OP_CHECKSIG
        script
    }

    /// Verify sequence constraints
    pub fn verify(script_sequence: Sequence, tx_sequence: Sequence) -> bool {
        let script_val = script_sequence.to_u32();
        let tx_val = tx_sequence.to_u32();

        if (script_val & Sequence::DISABLE_FLAG) != 0 {
            return true;
        }

        if (tx_val & Sequence::DISABLE_FLAG) != 0 {
            return false;
        }

        if (script_val & Sequence::TYPE_FLAG) != (tx_val & Sequence::TYPE_FLAG) {
            return false;
        }

        (tx_val & Sequence::LOCKTIME_MASK) >= (script_val & Sequence::LOCKTIME_MASK)
    }
}

/// Transaction with timelock support
#[derive(Debug, Clone)]
pub struct TimelockTransaction {
    pub version: u32,
    pub inputs: Vec<TimelockInput>,
    pub outputs: Vec<TimelockOutput>,
    pub locktime: LockTime,
}

#[derive(Debug, Clone)]
pub struct TimelockInput {
    pub txid: [u8; 32],
    pub vout: u32,
    pub script_sig: Vec<u8>,
    pub sequence: Sequence,
}

#[derive(Debug, Clone)]
pub struct TimelockOutput {
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
}

impl TimelockTransaction {
    pub fn new(locktime: LockTime) -> Self {
        Self {
            version: 2,
            inputs: Vec::new(),
            outputs: Vec::new(),
            locktime,
        }
    }

    pub fn add_input(&mut self, txid: [u8; 32], vout: u32, sequence: Sequence) {
        self.inputs.push(TimelockInput {
            txid,
            vout,
            script_sig: Vec::new(),
            sequence,
        });
    }

    pub fn add_output(&mut self, amount: u64, script_pubkey: Vec<u8>) {
        self.outputs.push(TimelockOutput {
            amount,
            script_pubkey,
        });
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut tx = Vec::new();

        tx.extend_from_slice(&self.version.to_le_bytes());
        tx.extend_from_slice(&varint_len(&vec![0u8; self.inputs.len()]));

        for input in &self.inputs {
            let mut txid_le = input.txid;
            txid_le.reverse();
            tx.extend_from_slice(&txid_le);
            tx.extend_from_slice(&input.vout.to_le_bytes());
            tx.extend_from_slice(&varint_len(&input.script_sig));
            tx.extend_from_slice(&input.script_sig);
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

    pub fn is_final(&self, block_height: u32, block_time: u32) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_locktime_compatibility() {
        let block_lt1 = LockTime::BlockHeight(500);
        let block_lt2 = LockTime::BlockHeight(600);
        let time_lt = LockTime::Timestamp(1609459200);

        assert!(block_lt1.is_compatible_with(&block_lt2));
        assert!(!block_lt1.is_compatible_with(&time_lt));
    }

    #[test]
    fn test_sequence_duration() {
        let block_seq = Sequence::from_blocks(144);
        assert_eq!(
            block_seq.get_locktime_duration(),
            Some(SequenceDuration::Blocks(144))
        );

        let time_seq = Sequence::from_time_intervals(10);
        assert_eq!(
            time_seq.get_locktime_duration(),
            Some(SequenceDuration::Time(5120))
        );
    }
}
