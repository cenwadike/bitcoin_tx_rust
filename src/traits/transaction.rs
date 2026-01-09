//! Transaction Traits for Sighash Flags and Timelocks
//!
//! This module provides common traits that can be implemented by different
//! transaction types to support sighash flags and timelock functionality.

use crate::sighash::SighashFlag;
use crate::timelocks::{LockTime, Sequence};

/// Trait for transactions that support sighash flags
pub trait SighashFlagSupport {
    /// Get the current sighash flag for a specific input
    fn get_sighash_flag(&self, input_index: usize) -> Option<SighashFlag>;

    /// Set the sighash flag for a specific input
    fn set_sighash_flag(&mut self, input_index: usize, flag: SighashFlag) -> Result<(), String>;

    /// Get all sighash flags for all inputs
    fn get_all_sighash_flags(&self) -> Vec<SighashFlag>;

    /// Check if ANYONECANPAY is enabled for a specific input
    fn has_anyonecanpay(&self, input_index: usize) -> bool {
        self.get_sighash_flag(input_index)
            .map(|f| f.has_anyonecanpay())
            .unwrap_or(false)
    }

    /// Get the base sighash type (ALL, NONE, or SINGLE) for an input
    fn get_base_sighash_type(&self, input_index: usize) -> Option<u8> {
        self.get_sighash_flag(input_index).map(|f| f.base_type())
    }
}

/// Trait for transactions that support absolute timelocks (nLockTime)
pub trait AbsoluteTimelockSupport {
    /// Get the transaction's locktime
    fn get_locktime(&self) -> LockTime;

    /// Set the transaction's locktime
    fn set_locktime(&mut self, locktime: LockTime);

    /// Check if the locktime is enabled (not all sequences are 0xffffffff)
    fn is_locktime_enabled(&self) -> bool;

    /// Check if the transaction is final at a given block height and time
    fn is_final_at(&self, block_height: u32, block_time: u32) -> bool;

    /// Get the locktime as a u32 value
    fn get_locktime_value(&self) -> u32 {
        self.get_locktime().to_u32()
    }
}

/// Trait for transactions that support relative timelocks (nSequence)
pub trait RelativeTimelockSupport {
    /// Get the sequence for a specific input
    fn get_sequence(&self, input_index: usize) -> Option<Sequence>;

    /// Set the sequence for a specific input
    fn set_sequence(&mut self, input_index: usize, sequence: Sequence) -> Result<(), String>;

    /// Get all sequences for all inputs
    fn get_all_sequences(&self) -> Vec<Sequence>;

    /// Check if relative timelock is enabled for a specific input
    fn is_relative_locktime_enabled(&self, input_index: usize) -> bool {
        self.get_sequence(input_index)
            .map(|s| s.is_relative_locktime_enabled())
            .unwrap_or(false)
    }

    /// Check if an input uses time-based relative locktime
    fn is_time_based_sequence(&self, input_index: usize) -> bool {
        self.get_sequence(input_index)
            .map(|s| s.is_time_based())
            .unwrap_or(false)
    }

    /// Get the locktime value for a specific input
    fn get_sequence_locktime_value(&self, input_index: usize) -> Option<u16> {
        self.get_sequence(input_index).map(|s| s.locktime_value())
    }
}

/// Combined trait for full timelock support
pub trait TimelockSupport: AbsoluteTimelockSupport + RelativeTimelockSupport {
    /// Check if any form of timelock is active
    fn has_any_timelock(&self) -> bool {
        if self.get_locktime().is_enabled() {
            return true;
        }

        for seq in self.get_all_sequences() {
            if seq.is_relative_locktime_enabled() {
                return true;
            }
        }

        false
    }

    /// Get a summary of all timelock constraints
    fn get_timelock_summary(&self) -> TimelockSummary {
        TimelockSummary {
            absolute_locktime: self.get_locktime(),
            relative_locktimes: self.get_all_sequences(),
        }
    }
}

/// Summary of all timelock constraints on a transaction
#[derive(Debug, Clone)]
pub struct TimelockSummary {
    pub absolute_locktime: LockTime,
    pub relative_locktimes: Vec<Sequence>,
}

impl TimelockSummary {
    /// Check if the transaction can be included at a given block height and time
    pub fn can_be_included_at(&self, block_height: u32, block_time: u32) -> bool {
        // Check absolute locktime
        match self.absolute_locktime {
            LockTime::BlockHeight(h) if block_height < h => return false,
            LockTime::Timestamp(t) if block_time < t => return false,
            _ => {}
        }

        // Note: Relative locktimes depend on when the UTXOs were confirmed,
        // which we don't track here. This would need additional context.
        true
    }
}

/// Trait for transactions that support signing with custom sighash flags
pub trait CustomSighashSigning {
    /// Sign a transaction input with a specific sighash flag
    fn sign_with_sighash(
        &self,
        input_index: usize,
        privkey: &[u8; 32],
        sighash_flag: SighashFlag,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>>;

    /// Sign multiple inputs with different sighash flags
    fn sign_multiple_with_sighash(
        &self,
        signing_data: &[(usize, Vec<u8>, SighashFlag)], // (index, privkey, flag)
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
}

/// Trait for transactions that support OP_CHECKLOCKTIMEVERIFY
pub trait OpCLTVSupport {
    /// Check if an input can satisfy OP_CHECKLOCKTIMEVERIFY with given locktime
    fn can_satisfy_cltv(&self, input_index: usize, script_locktime: LockTime) -> bool;

    /// Get the maximum locktime that can be satisfied for an input
    fn get_max_cltv_locktime(&self, input_index: usize) -> Option<LockTime>;
}

/// Trait for transactions that support OP_CHECKSEQUENCEVERIFY
pub trait OpCSVSupport {
    /// Check if an input can satisfy OP_CHECKSEQUENCEVERIFY with given sequence
    fn can_satisfy_csv(&self, input_index: usize, script_sequence: Sequence) -> bool;

    /// Get the maximum sequence that can be satisfied for an input
    fn get_max_csv_sequence(&self, input_index: usize) -> Option<Sequence>;
}

/// Builder trait for constructing transactions with timelocks
pub trait TimelockTransactionBuilder {
    /// Create a transaction with an absolute locktime
    fn with_absolute_locktime(locktime: LockTime) -> Self;

    /// Create a transaction with relative locktimes on inputs
    fn with_relative_locktimes(sequences: Vec<Sequence>) -> Self;

    /// Add an input with a specific sequence
    fn add_input_with_sequence(&mut self, txid: [u8; 32], vout: u32, sequence: Sequence);

    /// Add an input for CLTV script
    fn add_cltv_input(&mut self, txid: [u8; 32], vout: u32, script_locktime: LockTime);

    /// Add an input for CSV script
    fn add_csv_input(&mut self, txid: [u8; 32], vout: u32, script_sequence: Sequence);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timelock_summary() {
        let summary = TimelockSummary {
            absolute_locktime: LockTime::BlockHeight(500000),
            relative_locktimes: vec![
                Sequence::from_blocks(144),
                Sequence::from_time_intervals(10),
            ],
        };

        assert!(!summary.can_be_included_at(499999, 0));
        assert!(summary.can_be_included_at(500000, 0));
    }
}
