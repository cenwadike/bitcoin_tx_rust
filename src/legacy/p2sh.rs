//! P2SH Multisig Transaction with Trait Support
//!
//! This implements legacy P2SH multisig with full trait support

use crate::sighash::{LegacySighash, SighashFlag, SighashInput, SighashOutput};
use crate::timelocks::{LockTime, OpCheckLockTimeVerify, OpCheckSequenceVerify, Sequence};
use crate::transaction::*;
use crate::utils::*;
use num_integer::Integer;

/// P2SH Multisig Transaction with full trait support
#[derive(Debug, Clone)]
pub struct P2SHMultisigTransaction {
    version: u32,
    inputs: Vec<P2SHTxInput>,
    outputs: Vec<P2SHTxOutput>,
    locktime: LockTime,
    redeem_script: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct P2SHTxInput {
    pub txid: [u8; 32],
    pub vout: u32,
    pub sequence: Sequence,
    pub sighash_flag: SighashFlag,
    pub amount: u64,
}

#[derive(Debug, Clone)]
pub struct P2SHTxOutput {
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
}

impl P2SHMultisigTransaction {
    pub fn new(redeem_script: Vec<u8>) -> Self {
        Self {
            version: 1,
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

    /// Convert redeem script to P2SH address
    pub fn script_to_p2sh(script: &[u8], network: &str) -> String {
        let script_hash = hash160(script);

        let prefix = match network {
            "mainnet" => 0x05u8,
            "testnet" | "regtest" => 0xc4u8,
            _ => 0xc4u8,
        };

        let mut addr_bytes = vec![prefix];
        addr_bytes.extend_from_slice(&script_hash);

        let checksum = &hash256(&addr_bytes)[0..4];
        addr_bytes.extend_from_slice(checksum);

        base58_encode(&addr_bytes)
    }

    pub fn add_input(&mut self, txid: [u8; 32], vout: u32, amount: u64) {
        self.inputs.push(P2SHTxInput {
            txid,
            vout,
            sequence: Sequence::max(),
            sighash_flag: SighashFlag::All,
            amount,
        });
    }

    pub fn add_output(&mut self, amount: u64, script_pubkey: Vec<u8>) {
        self.outputs.push(P2SHTxOutput {
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

    /// Sign the P2SH multisig transaction with custom sighash flags per input
    pub fn sign(
        &self,
        privkeys_per_input: &[Vec<[u8; 32]>], // Vector of privkey sets, one per input
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if privkeys_per_input.len() != self.inputs.len() {
            return Err("Number of privkey sets must match number of inputs".into());
        }

        let mut script_sigs = Vec::new();

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
            let sighash = LegacySighash::compute(
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
                signature.push(input.sighash_flag.to_u8());
                signatures.push(signature);
            }

            // Build scriptSig: OP_0 <sig1> <sig2> ... <redeemScript>
            let mut script_sig = Vec::new();
            script_sig.push(0x00); // OP_0 for CHECKMULTISIG bug

            for sig in &signatures {
                script_sig.extend_from_slice(&pushbytes(sig));
            }

            script_sig.extend_from_slice(&pushbytes(&self.redeem_script));

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
impl SighashFlagSupport for P2SHMultisigTransaction {
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
impl AbsoluteTimelockSupport for P2SHMultisigTransaction {
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
impl RelativeTimelockSupport for P2SHMultisigTransaction {
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
impl TimelockSupport for P2SHMultisigTransaction {}

// Implement OpCLTVSupport trait
impl OpCLTVSupport for P2SHMultisigTransaction {
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
impl OpCSVSupport for P2SHMultisigTransaction {
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
impl TimelockTransactionBuilder for P2SHMultisigTransaction {
    fn with_absolute_locktime(locktime: LockTime) -> Self {
        Self {
            version: 1,
            inputs: Vec::new(),
            outputs: Vec::new(),
            locktime,
            redeem_script: Vec::new(),
        }
    }

    fn with_relative_locktimes(sequences: Vec<Sequence>) -> Self {
        let mut tx = Self::new(Vec::new());
        for seq in sequences {
            tx.inputs.push(P2SHTxInput {
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
        self.inputs.push(P2SHTxInput {
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

        self.inputs.push(P2SHTxInput {
            txid,
            vout,
            sequence: Sequence::enable_locktime(),
            sighash_flag: SighashFlag::All,
            amount: 0,
        });
    }

    fn add_csv_input(&mut self, txid: [u8; 32], vout: u32, script_sequence: Sequence) {
        self.inputs.push(P2SHTxInput {
            txid,
            vout,
            sequence: script_sequence,
            sighash_flag: SighashFlag::All,
            amount: 0,
        });
    }
}

/// Base58 encoding helper
fn base58_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    let mut num = num_bigint::BigUint::from_bytes_be(data);
    let base = num_bigint::BigUint::from(58u32);
    let zero = num_bigint::BigUint::from(0u32);

    let mut result = Vec::new();

    while num > zero {
        let (quotient, remainder) = num.div_rem(&base);
        result.push(ALPHABET[remainder.to_u32_digits()[0] as usize]);
        num = quotient;
    }

    for &byte in data {
        if byte == 0 {
            result.push(ALPHABET[0]);
        } else {
            break;
        }
    }

    result.reverse();
    String::from_utf8(result).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multisig_with_different_sighash_flags() {
        let privkey1 = [0x11u8; 32];
        let privkey2 = [0x22u8; 32];

        let pubkey1 = privkey_to_pubkey(&privkey1).unwrap();
        let pubkey2 = privkey_to_pubkey(&privkey2).unwrap();

        let redeem_script = P2SHMultisigTransaction::create_2of2_redeem_script(&pubkey1, &pubkey2);

        let mut tx = P2SHMultisigTransaction::new(redeem_script);

        // Add two inputs with different sighash flags
        tx.add_input([0x42; 32], 0, 100_000_000);
        tx.add_input([0x43; 32], 0, 200_000_000);

        tx.set_sighash_flag(0, SighashFlag::All).unwrap();
        tx.set_sighash_flag(1, SighashFlag::Single).unwrap();

        tx.add_output(140_000_000, vec![0x76, 0xa9, 0x14]);
        tx.add_output(150_000_000, vec![0x76, 0xa9, 0x14]);

        // Sign both inputs
        let signed = tx
            .sign(&[vec![privkey1, privkey2], vec![privkey1, privkey2]])
            .unwrap();

        assert!(!signed.is_empty());
    }

    #[test]
    fn test_2of3_multisig_with_timelock() {
        let privkey1 = [0x11u8; 32];
        let privkey2 = [0x22u8; 32];
        let privkey3 = [0x33u8; 32];

        let pubkey1 = privkey_to_pubkey(&privkey1).unwrap();
        let pubkey2 = privkey_to_pubkey(&privkey2).unwrap();
        let pubkey3 = privkey_to_pubkey(&privkey3).unwrap();

        let redeem_script =
            P2SHMultisigTransaction::create_2of3_redeem_script(&pubkey1, &pubkey2, &pubkey3);

        let mut tx = P2SHMultisigTransaction::new(redeem_script);
        tx.set_locktime(LockTime::BlockHeight(500000));

        tx.add_input([0x42; 32], 0, 100_000_000);
        tx.set_sequence(0, Sequence::enable_locktime()).unwrap();

        tx.add_output(99_000_000, vec![0x76, 0xa9, 0x14]);

        // Sign with only 2 of 3 keys
        let signed = tx.sign(&[vec![privkey1, privkey2]]).unwrap();

        assert!(!signed.is_empty());
        assert!(tx.can_satisfy_cltv(0, LockTime::BlockHeight(400000)));
    }
}
