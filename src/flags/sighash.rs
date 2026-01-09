//! Signature Hash (Sighash) Implementation with Trait Support
//!
//! This module implements the three generations of Bitcoin signature hash algorithms
//! with support for custom sighash flags through traits.

use crate::utils::*;

/// Sighash flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SighashFlag {
    All = 0x01,
    None = 0x02,
    Single = 0x03,
    AllAnyoneCanPay = 0x81,
    NoneAnyoneCanPay = 0x82,
    SingleAnyoneCanPay = 0x83,
    Default = 0x00, // Taproot only
}

impl SighashFlag {
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    pub fn to_u32(self) -> u32 {
        self as u32
    }

    pub fn has_anyonecanpay(self) -> bool {
        matches!(
            self,
            SighashFlag::AllAnyoneCanPay
                | SighashFlag::NoneAnyoneCanPay
                | SighashFlag::SingleAnyoneCanPay
        )
    }

    pub fn base_type(self) -> u8 {
        self.to_u8() & 0x1f
    }

    /// Parse sighash flag from byte
    pub fn from_u8(byte: u8) -> Result<Self, String> {
        match byte {
            0x00 => Ok(SighashFlag::Default),
            0x01 => Ok(SighashFlag::All),
            0x02 => Ok(SighashFlag::None),
            0x03 => Ok(SighashFlag::Single),
            0x81 => Ok(SighashFlag::AllAnyoneCanPay),
            0x82 => Ok(SighashFlag::NoneAnyoneCanPay),
            0x83 => Ok(SighashFlag::SingleAnyoneCanPay),
            _ => Err(format!("Invalid sighash flag: 0x{:02x}", byte)),
        }
    }

    /// Check if this is a valid flag for the given transaction type
    pub fn is_valid_for_legacy(&self) -> bool {
        !matches!(self, SighashFlag::Default)
    }

    pub fn is_valid_for_segwit(&self) -> bool {
        !matches!(self, SighashFlag::Default)
    }

    pub fn is_valid_for_taproot(&self) -> bool {
        true // All flags valid for Taproot
    }

    /// Get a human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            SighashFlag::All => "ALL: Signs all inputs and outputs",
            SighashFlag::None => "NONE: Signs all inputs, no outputs",
            SighashFlag::Single => "SINGLE: Signs all inputs, only corresponding output",
            SighashFlag::AllAnyoneCanPay => "ALL|ANYONECANPAY: Signs one input, all outputs",
            SighashFlag::NoneAnyoneCanPay => "NONE|ANYONECANPAY: Signs one input, no outputs",
            SighashFlag::SingleAnyoneCanPay => {
                "SINGLE|ANYONECANPAY: Signs one input, corresponding output"
            }
            SighashFlag::Default => "DEFAULT: Taproot default (same as ALL)",
        }
    }
}

/// Transaction input for sighash computation
#[derive(Debug, Clone)]
pub struct SighashInput {
    pub txid: [u8; 32],
    pub vout: u32,
    pub script_pubkey: Vec<u8>,
    pub amount: u64,
    pub sequence: u32,
}

/// Transaction output for sighash computation
#[derive(Debug, Clone)]
pub struct SighashOutput {
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
}

/// Sighash computation context
pub struct SighashContext {
    pub version: u32,
    pub inputs: Vec<SighashInput>,
    pub outputs: Vec<SighashOutput>,
    pub locktime: u32,
}

impl SighashContext {
    pub fn new(
        version: u32,
        inputs: Vec<SighashInput>,
        outputs: Vec<SighashOutput>,
        locktime: u32,
    ) -> Self {
        Self {
            version,
            inputs,
            outputs,
            locktime,
        }
    }
}

/// Legacy Sighash Calculator (Pre-SegWit)
pub struct LegacySighash;

impl LegacySighash {
    pub fn compute(
        version: u32,
        inputs: &[SighashInput],
        outputs: &[SighashOutput],
        input_index: usize,
        sighash_flag: SighashFlag,
        locktime: u32,
    ) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        if input_index >= inputs.len() {
            return Err("Input index out of bounds".into());
        }

        if !sighash_flag.is_valid_for_legacy() {
            return Err(format!("Invalid sighash flag for legacy: {:?}", sighash_flag).into());
        }

        let mut preimage = Vec::new();

        // Version
        preimage.extend_from_slice(&version.to_le_bytes());

        // Input count (affected by ANYONECANPAY)
        if sighash_flag.has_anyonecanpay() {
            preimage.push(0x01); // Only one input
        } else {
            preimage.extend_from_slice(&varint_len(&vec![0u8; inputs.len()]));
        }

        // Inputs
        if sighash_flag.has_anyonecanpay() {
            // Only the input being signed
            let input = &inputs[input_index];
            let mut txid_le = input.txid;
            txid_le.reverse();
            preimage.extend_from_slice(&txid_le);
            preimage.extend_from_slice(&input.vout.to_le_bytes());
            preimage.extend_from_slice(&varint_len(&input.script_pubkey));
            preimage.extend_from_slice(&input.script_pubkey);
            preimage.extend_from_slice(&input.sequence.to_le_bytes());
        } else {
            for (i, input) in inputs.iter().enumerate() {
                let mut txid_le = input.txid;
                txid_le.reverse();
                preimage.extend_from_slice(&txid_le);
                preimage.extend_from_slice(&input.vout.to_le_bytes());

                if i == input_index {
                    // Replace with scriptPubKey
                    preimage.extend_from_slice(&varint_len(&input.script_pubkey));
                    preimage.extend_from_slice(&input.script_pubkey);
                } else {
                    // Empty scriptSig
                    preimage.push(0x00);
                }

                // Sequence handling based on sighash type
                match sighash_flag.base_type() {
                    0x02 | 0x03 if i != input_index => {
                        // NONE or SINGLE: zero out sequence for other inputs
                        preimage.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
                    }
                    _ => {
                        preimage.extend_from_slice(&input.sequence.to_le_bytes());
                    }
                }
            }
        }

        // Output count
        let output_count = match sighash_flag.base_type() {
            0x02 => 0, // NONE: no outputs
            0x03 => {
                // SINGLE: outputs up to and including input_index
                if input_index >= outputs.len() {
                    return Err("SINGLE: input index >= output count".into());
                }
                input_index + 1
            }
            _ => outputs.len(), // ALL: all outputs
        };

        preimage.extend_from_slice(&varint_len(&vec![0u8; output_count]));

        // Outputs
        for (i, output) in outputs.iter().take(output_count).enumerate() {
            if sighash_flag.base_type() == 0x03 && i < input_index {
                // SINGLE: null outputs before input_index
                preimage.extend_from_slice(&[0xff; 8]); // -1 value
                preimage.push(0x00); // empty scriptPubKey
            } else {
                preimage.extend_from_slice(&output.amount.to_le_bytes());
                preimage.extend_from_slice(&varint_len(&output.script_pubkey));
                preimage.extend_from_slice(&output.script_pubkey);
            }
        }

        // Locktime
        preimage.extend_from_slice(&locktime.to_le_bytes());

        // Sighash flag (4 bytes)
        preimage.extend_from_slice(&sighash_flag.to_u32().to_le_bytes());

        // Double SHA-256
        Ok(hash256(&preimage))
    }

    /// Compute sighash from context
    pub fn compute_from_context(
        context: &SighashContext,
        input_index: usize,
        sighash_flag: SighashFlag,
    ) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        Self::compute(
            context.version,
            &context.inputs,
            &context.outputs,
            input_index,
            sighash_flag,
            context.locktime,
        )
    }
}

/// SegWit v0 Sighash Calculator (BIP-143)
pub struct SegwitV0Sighash;

impl SegwitV0Sighash {
    pub fn compute(
        version: u32,
        inputs: &[SighashInput],
        outputs: &[SighashOutput],
        input_index: usize,
        sighash_flag: SighashFlag,
        locktime: u32,
    ) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        if input_index >= inputs.len() {
            return Err("Input index out of bounds".into());
        }

        if !sighash_flag.is_valid_for_segwit() {
            return Err(format!("Invalid sighash flag for segwit: {:?}", sighash_flag).into());
        }

        let input = &inputs[input_index];
        let mut preimage = Vec::new();

        // Version
        preimage.extend_from_slice(&version.to_le_bytes());

        // hashPrevouts
        let hash_prevouts = if sighash_flag.has_anyonecanpay() {
            [0u8; 32]
        } else {
            let mut prevouts = Vec::new();
            for inp in inputs {
                let mut txid_le = inp.txid;
                txid_le.reverse();
                prevouts.extend_from_slice(&txid_le);
                prevouts.extend_from_slice(&inp.vout.to_le_bytes());
            }
            hash256(&prevouts)
        };
        preimage.extend_from_slice(&hash_prevouts);

        // hashSequence
        let hash_sequence = if sighash_flag.has_anyonecanpay()
            || sighash_flag.base_type() == 0x02
            || sighash_flag.base_type() == 0x03
        {
            [0u8; 32]
        } else {
            let mut sequences = Vec::new();
            for inp in inputs {
                sequences.extend_from_slice(&inp.sequence.to_le_bytes());
            }
            hash256(&sequences)
        };
        preimage.extend_from_slice(&hash_sequence);

        // outpoint being spent
        let mut txid_le = input.txid;
        txid_le.reverse();
        preimage.extend_from_slice(&txid_le);
        preimage.extend_from_slice(&input.vout.to_le_bytes());

        // scriptCode
        preimage.extend_from_slice(&varint_len(&input.script_pubkey));
        preimage.extend_from_slice(&input.script_pubkey);

        // value of the input
        preimage.extend_from_slice(&input.amount.to_le_bytes());

        // sequence
        preimage.extend_from_slice(&input.sequence.to_le_bytes());

        // hashOutputs
        let hash_outputs = if sighash_flag.base_type() == 0x01 {
            // ALL: hash all outputs
            let mut outs = Vec::new();
            for output in outputs {
                outs.extend_from_slice(&output.amount.to_le_bytes());
                outs.extend_from_slice(&varint_len(&output.script_pubkey));
                outs.extend_from_slice(&output.script_pubkey);
            }
            hash256(&outs)
        } else if sighash_flag.base_type() == 0x03 && input_index < outputs.len() {
            // SINGLE: hash only the corresponding output
            let output = &outputs[input_index];
            let mut out = Vec::new();
            out.extend_from_slice(&output.amount.to_le_bytes());
            out.extend_from_slice(&varint_len(&output.script_pubkey));
            out.extend_from_slice(&output.script_pubkey);
            hash256(&out)
        } else {
            // NONE or SINGLE with no corresponding output
            [0u8; 32]
        };
        preimage.extend_from_slice(&hash_outputs);

        // locktime
        preimage.extend_from_slice(&locktime.to_le_bytes());

        // sighash flag (4 bytes)
        preimage.extend_from_slice(&sighash_flag.to_u32().to_le_bytes());

        // Double SHA-256
        Ok(hash256(&preimage))
    }

    /// Compute sighash from context
    pub fn compute_from_context(
        context: &SighashContext,
        input_index: usize,
        sighash_flag: SighashFlag,
    ) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        Self::compute(
            context.version,
            &context.inputs,
            &context.outputs,
            input_index,
            sighash_flag,
            context.locktime,
        )
    }
}

/// Taproot Sighash Calculator (BIP-341)
pub struct TaprootSighash;

impl TaprootSighash {
    pub fn compute(
        version: u32,
        inputs: &[SighashInput],
        outputs: &[SighashOutput],
        input_index: usize,
        sighash_flag: SighashFlag,
        locktime: u32,
        annex_present: bool,
    ) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        if input_index >= inputs.len() {
            return Err("Input index out of bounds".into());
        }

        let mut sig_msg = Vec::new();

        // Epoch (0x00)
        sig_msg.push(0x00);

        // Sighash type
        sig_msg.push(sighash_flag.to_u8());

        // Version
        sig_msg.extend_from_slice(&version.to_le_bytes());

        // Locktime
        sig_msg.extend_from_slice(&locktime.to_le_bytes());

        // sha_prevouts
        let sha_prevouts = if sighash_flag.has_anyonecanpay() {
            [0u8; 32]
        } else {
            let mut prevouts = Vec::new();
            for inp in inputs {
                let mut txid_le = inp.txid;
                txid_le.reverse();
                prevouts.extend_from_slice(&txid_le);
                prevouts.extend_from_slice(&inp.vout.to_le_bytes());
            }
            sha256(&prevouts)
        };
        sig_msg.extend_from_slice(&sha_prevouts);

        // sha_amounts
        let sha_amounts = if sighash_flag.has_anyonecanpay() {
            [0u8; 32]
        } else {
            let mut amounts = Vec::new();
            for inp in inputs {
                amounts.extend_from_slice(&inp.amount.to_le_bytes());
            }
            sha256(&amounts)
        };
        sig_msg.extend_from_slice(&sha_amounts);

        // sha_scriptpubkeys
        let sha_scriptpubkeys = if sighash_flag.has_anyonecanpay() {
            [0u8; 32]
        } else {
            let mut scriptpubkeys = Vec::new();
            for inp in inputs {
                scriptpubkeys.extend_from_slice(&varint_len(&inp.script_pubkey));
                scriptpubkeys.extend_from_slice(&inp.script_pubkey);
            }
            sha256(&scriptpubkeys)
        };
        sig_msg.extend_from_slice(&sha_scriptpubkeys);

        // sha_sequences
        let sha_sequences = if sighash_flag.has_anyonecanpay()
            || sighash_flag.base_type() == 0x02
            || sighash_flag.base_type() == 0x03
        {
            [0u8; 32]
        } else {
            let mut sequences = Vec::new();
            for inp in inputs {
                sequences.extend_from_slice(&inp.sequence.to_le_bytes());
            }
            sha256(&sequences)
        };
        sig_msg.extend_from_slice(&sha_sequences);

        // sha_outputs
        let sha_outputs =
            if sighash_flag.base_type() == 0x01 || sighash_flag == SighashFlag::Default {
                let mut outs = Vec::new();
                for output in outputs {
                    outs.extend_from_slice(&output.amount.to_le_bytes());
                    outs.extend_from_slice(&varint_len(&output.script_pubkey));
                    outs.extend_from_slice(&output.script_pubkey);
                }
                sha256(&outs)
            } else if sighash_flag.base_type() == 0x03 && input_index < outputs.len() {
                let output = &outputs[input_index];
                let mut out = Vec::new();
                out.extend_from_slice(&output.amount.to_le_bytes());
                out.extend_from_slice(&varint_len(&output.script_pubkey));
                out.extend_from_slice(&output.script_pubkey);
                sha256(&out)
            } else {
                [0u8; 32]
            };
        sig_msg.extend_from_slice(&sha_outputs);

        // spend_type
        let spend_type = if annex_present { 0x01 } else { 0x00 };
        sig_msg.push(spend_type);

        // input_index
        sig_msg.extend_from_slice(&(input_index as u32).to_le_bytes());

        // If ANYONECANPAY, include details of input being signed
        if sighash_flag.has_anyonecanpay() {
            let input = &inputs[input_index];
            let mut txid_le = input.txid;
            txid_le.reverse();
            sig_msg.extend_from_slice(&txid_le);
            sig_msg.extend_from_slice(&input.vout.to_le_bytes());
            sig_msg.extend_from_slice(&input.amount.to_le_bytes());
            sig_msg.extend_from_slice(&varint_len(&input.script_pubkey));
            sig_msg.extend_from_slice(&input.script_pubkey);
            sig_msg.extend_from_slice(&input.sequence.to_le_bytes());
        }

        // If SINGLE, include output index
        if sighash_flag.base_type() == 0x03 {
            if input_index >= outputs.len() {
                return Err("SINGLE: input index >= output count".into());
            }
            let output = &outputs[input_index];
            sig_msg.extend_from_slice(&output.amount.to_le_bytes());
            sig_msg.extend_from_slice(&varint_len(&output.script_pubkey));
            sig_msg.extend_from_slice(&output.script_pubkey);
        }

        // Tagged hash
        let tag = b"TapSighash";
        let tag_hash = sha256(tag);
        let mut tagged_preimage = Vec::new();
        tagged_preimage.extend_from_slice(&tag_hash);
        tagged_preimage.extend_from_slice(&tag_hash);
        tagged_preimage.extend_from_slice(&sig_msg);

        Ok(sha256(&tagged_preimage))
    }

    /// Compute sighash from context
    pub fn compute_from_context(
        context: &SighashContext,
        input_index: usize,
        sighash_flag: SighashFlag,
        annex_present: bool,
    ) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        Self::compute(
            context.version,
            &context.inputs,
            &context.outputs,
            input_index,
            sighash_flag,
            context.locktime,
            annex_present,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sighash_flag_parsing() {
        assert_eq!(SighashFlag::from_u8(0x01).unwrap(), SighashFlag::All);
        assert_eq!(
            SighashFlag::from_u8(0x81).unwrap(),
            SighashFlag::AllAnyoneCanPay
        );
        assert!(SighashFlag::from_u8(0xFF).is_err());
    }

    #[test]
    fn test_sighash_flag_validation() {
        assert!(SighashFlag::All.is_valid_for_legacy());
        assert!(!SighashFlag::Default.is_valid_for_legacy());
        assert!(SighashFlag::Default.is_valid_for_taproot());
    }
}
