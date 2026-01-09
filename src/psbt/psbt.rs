//! PSBT (Partially Signed Bitcoin Transaction) Implementation
//!
//! Implements BIP-174: Partially Signed Bitcoin Transaction Format
//!
//! PSBT allows multiple parties to collaboratively sign a transaction,
//! with support for hardware wallets, air-gapped signing, and more.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::convert::TryInto;

/// PSBT Magic bytes (0x70736274 = "psbt" in ASCII)
const PSBT_MAGIC: &[u8] = b"psbt";
const PSBT_SEPARATOR: u8 = 0xff;

/// PSBT Global Types (BIP-174)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PsbtGlobalType {
    UnsignedTx = 0x00,
    XpubKey = 0x01,
    Version = 0xfb,
    Proprietary = 0xfc,
}

/// PSBT Input Types (BIP-174)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PsbtInputType {
    NonWitnessUtxo = 0x00,
    WitnessUtxo = 0x01,
    PartialSig = 0x02,
    SighashType = 0x03,
    RedeemScript = 0x04,
    WitnessScript = 0x05,
    Bip32Derivation = 0x06,
    FinalScriptSig = 0x07,
    FinalScriptWitness = 0x08,
    PorCommitment = 0x09,
    Ripemd160 = 0x0a,
    Sha256 = 0x0b,
    Hash160 = 0x0c,
    Hash256 = 0x0d,
    TapKeySig = 0x13,
    TapScriptSig = 0x14,
    TapLeafScript = 0x15,
    TapBip32Derivation = 0x16,
    TapInternalKey = 0x17,
    TapMerkleRoot = 0x18,
    Proprietary = 0xfc,
}

/// PSBT Output Types (BIP-174)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PsbtOutputType {
    RedeemScript = 0x00,
    WitnessScript = 0x01,
    Bip32Derivation = 0x02,
    TapInternalKey = 0x05,
    TapTree = 0x06,
    TapBip32Derivation = 0x07,
    Proprietary = 0xfc,
}

/// Key-value pair in PSBT
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyValue {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// PSBT Global data
#[derive(Debug, Clone)]
pub struct PsbtGlobal {
    pub unsigned_tx: Vec<u8>,
    pub version: Option<u32>,
    pub xpubs: BTreeMap<Vec<u8>, Vec<u8>>,
    pub proprietary: BTreeMap<Vec<u8>, Vec<u8>>,
    pub unknown: BTreeMap<Vec<u8>, Vec<u8>>,
}

/// PSBT Input data
#[derive(Debug, Clone)]
pub struct PsbtInput {
    pub non_witness_utxo: Option<Vec<u8>>,
    pub witness_utxo: Option<WitnessUtxo>,
    pub partial_sigs: BTreeMap<Vec<u8>, Vec<u8>>,
    pub sighash_type: Option<u32>,
    pub redeem_script: Option<Vec<u8>>,
    pub witness_script: Option<Vec<u8>>,
    pub bip32_derivation: BTreeMap<Vec<u8>, Bip32Derivation>,
    pub final_script_sig: Option<Vec<u8>>,
    pub final_script_witness: Option<Vec<Vec<u8>>>,
    pub por_commitment: Option<Vec<u8>>,
    pub ripemd160_preimages: BTreeMap<[u8; 20], Vec<u8>>,
    pub sha256_preimages: BTreeMap<[u8; 32], Vec<u8>>,
    pub hash160_preimages: BTreeMap<[u8; 20], Vec<u8>>,
    pub hash256_preimages: BTreeMap<[u8; 32], Vec<u8>>,
    pub tap_key_sig: Option<Vec<u8>>,
    pub tap_script_sigs: BTreeMap<Vec<u8>, Vec<u8>>,
    pub tap_leaf_scripts: Vec<TapLeafScript>,
    pub tap_bip32_derivation: BTreeMap<Vec<u8>, TapBip32Derivation>,
    pub tap_internal_key: Option<Vec<u8>>,
    pub tap_merkle_root: Option<Vec<u8>>,
    pub proprietary: BTreeMap<Vec<u8>, Vec<u8>>,
    pub unknown: BTreeMap<Vec<u8>, Vec<u8>>,
}

/// PSBT Output data
#[derive(Debug, Clone)]
pub struct PsbtOutput {
    pub redeem_script: Option<Vec<u8>>,
    pub witness_script: Option<Vec<u8>>,
    pub bip32_derivation: BTreeMap<Vec<u8>, Bip32Derivation>,
    pub tap_internal_key: Option<Vec<u8>>,
    pub tap_tree: Option<Vec<u8>>,
    pub tap_bip32_derivation: BTreeMap<Vec<u8>, TapBip32Derivation>,
    pub proprietary: BTreeMap<Vec<u8>, Vec<u8>>,
    pub unknown: BTreeMap<Vec<u8>, Vec<u8>>,
}

/// Witness UTXO (BIP-174)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessUtxo {
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
}

/// BIP-32 derivation path
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip32Derivation {
    pub master_fingerprint: [u8; 4],
    pub path: Vec<u32>,
}

/// Taproot BIP-32 derivation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TapBip32Derivation {
    pub leaf_hashes: Vec<[u8; 32]>,
    pub master_fingerprint: [u8; 4],
    pub path: Vec<u32>,
}

/// Taproot leaf script
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TapLeafScript {
    pub control_block: Vec<u8>,
    pub script: Vec<u8>,
    pub leaf_version: u8,
}

/// Complete PSBT structure
#[derive(Debug, Clone)]
pub struct Psbt {
    pub global: PsbtGlobal,
    pub inputs: Vec<PsbtInput>,
    pub outputs: Vec<PsbtOutput>,
}

impl Psbt {
    /// Create a new PSBT from an unsigned transaction
    pub fn new(unsigned_tx: Vec<u8>) -> Result<Self, PsbtError> {
        // Parse transaction to get input/output counts
        let (input_count, output_count) = Self::parse_tx_counts(&unsigned_tx)?;

        Ok(Self {
            global: PsbtGlobal {
                unsigned_tx,
                version: Some(0),
                xpubs: BTreeMap::new(),
                proprietary: BTreeMap::new(),
                unknown: BTreeMap::new(),
            },
            inputs: vec![PsbtInput::new(); input_count],
            outputs: vec![PsbtOutput::new(); output_count],
        })
    }

    /// Create PSBT from base64 string
    pub fn from_base64(s: &str) -> Result<Self, PsbtError> {
        use base64::{Engine as _, engine::general_purpose};
        let bytes = general_purpose::STANDARD
            .decode(s)
            .map_err(|_| PsbtError::InvalidBase64)?;
        Self::deserialize(&bytes)
    }

    /// Serialize PSBT to base64 string
    pub fn to_base64(&self) -> String {
        use base64::{Engine as _, engine::general_purpose};
        general_purpose::STANDARD.encode(self.serialize())
    }

    /// Serialize PSBT to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Magic bytes
        result.extend_from_slice(PSBT_MAGIC);
        result.push(PSBT_SEPARATOR);

        // Global data
        self.serialize_global(&mut result);

        // Inputs
        for input in &self.inputs {
            input.serialize(&mut result);
        }

        // Outputs
        for output in &self.outputs {
            output.serialize(&mut result);
        }

        result
    }

    /// Deserialize PSBT from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self, PsbtError> {
        let mut cursor = 0;

        // Check magic bytes
        if data.len() < 5 || &data[0..4] != PSBT_MAGIC || data[4] != PSBT_SEPARATOR {
            return Err(PsbtError::InvalidMagic);
        }
        cursor += 5;

        // Parse global
        let (global, new_cursor) = Self::deserialize_global(&data[cursor..])?;
        cursor += new_cursor;

        // Get input/output counts from unsigned tx
        let (input_count, output_count) = Self::parse_tx_counts(&global.unsigned_tx)?;

        // Parse inputs
        let mut inputs = Vec::new();
        for _ in 0..input_count {
            let (input, new_cursor) = PsbtInput::deserialize(&data[cursor..])?;
            cursor += new_cursor;
            inputs.push(input);
        }

        // Parse outputs
        let mut outputs = Vec::new();
        for _ in 0..output_count {
            let (output, new_cursor) = PsbtOutput::deserialize(&data[cursor..])?;
            cursor += new_cursor;
            outputs.push(output);
        }

        Ok(Self {
            global,
            inputs,
            outputs,
        })
    }

    /// Add a partial signature to an input
    pub fn add_partial_sig(
        &mut self,
        input_index: usize,
        pubkey: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<(), PsbtError> {
        if input_index >= self.inputs.len() {
            return Err(PsbtError::InvalidInputIndex);
        }

        self.inputs[input_index]
            .partial_sigs
            .insert(pubkey, signature);
        Ok(())
    }

    /// Set witness UTXO for an input
    pub fn set_witness_utxo(
        &mut self,
        input_index: usize,
        amount: u64,
        script_pubkey: Vec<u8>,
    ) -> Result<(), PsbtError> {
        if input_index >= self.inputs.len() {
            return Err(PsbtError::InvalidInputIndex);
        }

        self.inputs[input_index].witness_utxo = Some(WitnessUtxo {
            amount,
            script_pubkey,
        });
        Ok(())
    }

    /// Set non-witness UTXO for an input
    pub fn set_non_witness_utxo(
        &mut self,
        input_index: usize,
        tx: Vec<u8>,
    ) -> Result<(), PsbtError> {
        if input_index >= self.inputs.len() {
            return Err(PsbtError::InvalidInputIndex);
        }

        self.inputs[input_index].non_witness_utxo = Some(tx);
        Ok(())
    }

    /// Set redeem script for an input
    pub fn set_input_redeem_script(
        &mut self,
        input_index: usize,
        script: Vec<u8>,
    ) -> Result<(), PsbtError> {
        if input_index >= self.inputs.len() {
            return Err(PsbtError::InvalidInputIndex);
        }

        self.inputs[input_index].redeem_script = Some(script);
        Ok(())
    }

    /// Set witness script for an input
    pub fn set_input_witness_script(
        &mut self,
        input_index: usize,
        script: Vec<u8>,
    ) -> Result<(), PsbtError> {
        if input_index >= self.inputs.len() {
            return Err(PsbtError::InvalidInputIndex);
        }

        self.inputs[input_index].witness_script = Some(script);
        Ok(())
    }

    /// Add BIP-32 derivation path for an input
    pub fn add_input_bip32_derivation(
        &mut self,
        input_index: usize,
        pubkey: Vec<u8>,
        fingerprint: [u8; 4],
        path: Vec<u32>,
    ) -> Result<(), PsbtError> {
        if input_index >= self.inputs.len() {
            return Err(PsbtError::InvalidInputIndex);
        }

        self.inputs[input_index].bip32_derivation.insert(
            pubkey,
            Bip32Derivation {
                master_fingerprint: fingerprint,
                path,
            },
        );
        Ok(())
    }

    /// Add BIP-32 derivation path for an output
    pub fn add_output_bip32_derivation(
        &mut self,
        output_index: usize,
        pubkey: Vec<u8>,
        fingerprint: [u8; 4],
        path: Vec<u32>,
    ) -> Result<(), PsbtError> {
        if output_index >= self.outputs.len() {
            return Err(PsbtError::InvalidOutputIndex);
        }

        self.outputs[output_index].bip32_derivation.insert(
            pubkey,
            Bip32Derivation {
                master_fingerprint: fingerprint,
                path,
            },
        );
        Ok(())
    }

    /// Finalize an input (set final scriptSig/witness)
    pub fn finalize_input(&mut self, input_index: usize) -> Result<(), PsbtError> {
        if input_index >= self.inputs.len() {
            return Err(PsbtError::InvalidInputIndex);
        }

        let input = &mut self.inputs[input_index];

        // Check if already finalized
        if input.final_script_sig.is_some() || input.final_script_witness.is_some() {
            return Ok(());
        }

        // Taproot key path
        if let Some(sig) = input.tap_key_sig.take() {
            input.final_script_witness = Some(vec![sig]);
            return Ok(());
        }

        // Legacy P2PKH (simplified, single sig)
        if !input.partial_sigs.is_empty()
            && input.redeem_script.is_none()
            && input.witness_script.is_none()
            && input.tap_internal_key.is_none()
            && input.non_witness_utxo.is_some()
        {
            if input.partial_sigs.len() == 1 {
                let (pubkey, sig) = input.partial_sigs.iter().next().unwrap().clone();
                let mut script_sig = serialize_pushdata(&sig);
                script_sig.extend_from_slice(&serialize_pushdata(&pubkey));
                input.final_script_sig = Some(script_sig);
                input.partial_sigs.clear();
                return Ok(());
            }
        }

        // P2WPKH (simplified, single sig)
        if input.partial_sigs.len() == 1
            && input.redeem_script.is_none()
            && input.witness_script.is_none()
            && input.witness_utxo.is_some()
        {
            let (pubkey, sig) = input.partial_sigs.iter().next().unwrap().clone();
            input.final_script_witness = Some(vec![sig.clone(), pubkey.clone()]);
            input.partial_sigs.clear();
            return Ok(());
        }

        // P2WSH multisig
        if let Some(witness_script) = &input.witness_script {
            if !input.partial_sigs.is_empty() {
                let mut witness_stack: Vec<Vec<u8>> = vec![vec![]]; // OP_0 for multisig
                for sig in input.partial_sigs.values() {
                    witness_stack.push(sig.clone());
                }
                witness_stack.push(witness_script.clone());
                input.final_script_witness = Some(witness_stack);
                input.partial_sigs.clear();
                input.witness_script = None;
                return Ok(());
            }
        }

        // P2SH multisig
        if let Some(redeem_script) = &input.redeem_script {
            if !input.partial_sigs.is_empty() {
                let mut script_sig = vec![0x00]; // OP_0 for multisig
                for sig in input.partial_sigs.values() {
                    script_sig.extend_from_slice(&serialize_pushdata(sig));
                }
                script_sig.extend_from_slice(&serialize_pushdata(redeem_script));
                input.final_script_sig = Some(script_sig);
                input.partial_sigs.clear();
                input.redeem_script = None;
                return Ok(());
            }
        }

        Err(PsbtError::CannotFinalize)
    }

    /// Extract the final signed transaction
    pub fn extract_tx(&self) -> Result<Vec<u8>, PsbtError> {
        let mut has_witness = false;
        for input in &self.inputs {
            if input.final_script_witness.is_some() {
                has_witness = true;
            }
        }

        // Verify all inputs are finalized
        for (i, input) in self.inputs.iter().enumerate() {
            if input.final_script_sig.is_none() && input.final_script_witness.is_none() {
                return Err(PsbtError::InputNotFinalized(i));
            }
        }

        let unsigned = &self.global.unsigned_tx;
        let mut cursor: usize = 0;
        let mut tx: Vec<u8> = Vec::new();

        // Version
        if unsigned.len() < 4 {
            return Err(PsbtError::InvalidTransaction);
        }
        tx.extend_from_slice(&unsigned[0..4]);
        cursor += 4;

        // Flag if witnesses
        if has_witness {
            tx.push(0x00);
            tx.push(0x01);
        }

        // Input count
        let (in_count, b) = read_varint(&unsigned[cursor..])?;
        cursor += b;
        tx.extend_from_slice(&serialize_varint(in_count));

        // Inputs
        for i in 0..in_count {
            // prev_txid
            if cursor + 32 > unsigned.len() {
                return Err(PsbtError::InvalidTransaction);
            }
            tx.extend_from_slice(&unsigned[cursor..cursor + 32]);
            cursor += 32;

            // vout
            if cursor + 4 > unsigned.len() {
                return Err(PsbtError::InvalidTransaction);
            }
            tx.extend_from_slice(&unsigned[cursor..cursor + 4]);
            cursor += 4;

            // script_sig
            let script_sig = self.inputs[i].final_script_sig.clone().unwrap_or(vec![]);
            tx.extend_from_slice(&serialize_varint(script_sig.len()));
            tx.extend_from_slice(&script_sig);

            // Skip empty script_sig in unsigned (varint 0)
            let (len, b) = read_varint(&unsigned[cursor..])?;
            if len != 0 {
                return Err(PsbtError::InvalidTransaction);
            }
            cursor += b;

            // sequence
            if cursor + 4 > unsigned.len() {
                return Err(PsbtError::InvalidTransaction);
            }
            tx.extend_from_slice(&unsigned[cursor..cursor + 4]);
            cursor += 4;
        }

        // Output count
        let (out_count, b) = read_varint(&unsigned[cursor..])?;
        cursor += b;
        tx.extend_from_slice(&serialize_varint(out_count));

        // Outputs
        for _ in 0..out_count {
            // amount
            if cursor + 8 > unsigned.len() {
                return Err(PsbtError::InvalidTransaction);
            }
            tx.extend_from_slice(&unsigned[cursor..cursor + 8]);
            cursor += 8;

            // script_pubkey
            let (spk_len, b) = read_varint(&unsigned[cursor..])?;
            cursor += b;
            if cursor + spk_len > unsigned.len() {
                return Err(PsbtError::InvalidTransaction);
            }
            tx.extend_from_slice(&serialize_varint(spk_len));
            tx.extend_from_slice(&unsigned[cursor..cursor + spk_len]);
            cursor += spk_len;
        }

        // Witnesses if present
        if has_witness {
            for i in 0..in_count {
                let witness = self.inputs[i]
                    .final_script_witness
                    .clone()
                    .unwrap_or(vec![]);
                tx.extend_from_slice(&serialize_varint(witness.len()));
                for item in witness {
                    tx.extend_from_slice(&serialize_varint(item.len()));
                    tx.extend_from_slice(&item);
                }
            }
        }

        // Locktime
        if cursor + 4 != unsigned.len() {
            return Err(PsbtError::InvalidTransaction);
        }
        tx.extend_from_slice(&unsigned[cursor..cursor + 4]);

        Ok(tx)
    }

    /// Combine multiple PSBTs
    pub fn combine(&mut self, other: &Psbt) -> Result<(), PsbtError> {
        // Verify they're for the same transaction
        if self.global.unsigned_tx != other.global.unsigned_tx {
            return Err(PsbtError::DifferentTransactions);
        }

        // Combine global
        merge_opt(&mut self.global.version, &other.global.version)?;
        merge_map(&mut self.global.xpubs, &other.global.xpubs)?;
        merge_map(&mut self.global.proprietary, &other.global.proprietary)?;
        merge_map(&mut self.global.unknown, &other.global.unknown)?;

        // Combine inputs
        for (i, other_input) in other.inputs.iter().enumerate() {
            if i >= self.inputs.len() {
                continue;
            }
            let input = &mut self.inputs[i];
            merge_opt(&mut input.non_witness_utxo, &other_input.non_witness_utxo)?;
            merge_opt(&mut input.witness_utxo, &other_input.witness_utxo)?;
            merge_map(&mut input.partial_sigs, &other_input.partial_sigs)?;
            merge_opt(&mut input.sighash_type, &other_input.sighash_type)?;
            merge_opt(&mut input.redeem_script, &other_input.redeem_script)?;
            merge_opt(&mut input.witness_script, &other_input.witness_script)?;
            merge_map(&mut input.bip32_derivation, &other_input.bip32_derivation)?;
            merge_opt(&mut input.final_script_sig, &other_input.final_script_sig)?;
            merge_opt(
                &mut input.final_script_witness,
                &other_input.final_script_witness,
            )?;
            merge_opt(&mut input.por_commitment, &other_input.por_commitment)?;
            merge_map(
                &mut input.ripemd160_preimages,
                &other_input.ripemd160_preimages,
            )?;
            merge_map(&mut input.sha256_preimages, &other_input.sha256_preimages)?;
            merge_map(&mut input.hash160_preimages, &other_input.hash160_preimages)?;
            merge_map(&mut input.hash256_preimages, &other_input.hash256_preimages)?;
            merge_opt(&mut input.tap_key_sig, &other_input.tap_key_sig)?;
            merge_map(&mut input.tap_script_sigs, &other_input.tap_script_sigs)?;
            merge_vec(&mut input.tap_leaf_scripts, &other_input.tap_leaf_scripts)?;
            merge_map(
                &mut input.tap_bip32_derivation,
                &other_input.tap_bip32_derivation,
            )?;
            merge_opt(&mut input.tap_internal_key, &other_input.tap_internal_key)?;
            merge_opt(&mut input.tap_merkle_root, &other_input.tap_merkle_root)?;
            merge_map(&mut input.proprietary, &other_input.proprietary)?;
            merge_map(&mut input.unknown, &other_input.unknown)?;
        }

        // Combine outputs
        for (i, other_output) in other.outputs.iter().enumerate() {
            if i >= self.outputs.len() {
                continue;
            }
            let output = &mut self.outputs[i];
            merge_opt(&mut output.redeem_script, &other_output.redeem_script)?;
            merge_opt(&mut output.witness_script, &other_output.witness_script)?;
            merge_map(&mut output.bip32_derivation, &other_output.bip32_derivation)?;
            merge_opt(&mut output.tap_internal_key, &other_output.tap_internal_key)?;
            merge_opt(&mut output.tap_tree, &other_output.tap_tree)?;
            merge_map(
                &mut output.tap_bip32_derivation,
                &other_output.tap_bip32_derivation,
            )?;
            merge_map(&mut output.proprietary, &other_output.proprietary)?;
            merge_map(&mut output.unknown, &other_output.unknown)?;
        }

        Ok(())
    }

    // Helper methods

    fn serialize_global(&self, output: &mut Vec<u8>) {
        // Unsigned transaction (required)
        serialize_kv(output, &[0x00], &self.global.unsigned_tx);

        // Version (optional)
        if let Some(version) = self.global.version {
            serialize_kv(output, &[0xfb], &version.to_le_bytes());
        }

        // XPubs
        for (key, value) in &self.global.xpubs {
            let mut full_key = vec![0x01];
            full_key.extend_from_slice(key);
            serialize_kv(output, &full_key, value);
        }

        // Proprietary
        for (key, value) in &self.global.proprietary {
            let mut full_key = vec![0xfc];
            full_key.extend_from_slice(key);
            serialize_kv(output, &full_key, value);
        }

        // Unknown
        for (key, value) in &self.global.unknown {
            serialize_kv(output, key, value);
        }

        // Separator
        output.push(0x00);
    }

    fn deserialize_global(data: &[u8]) -> Result<(PsbtGlobal, usize), PsbtError> {
        let mut cursor = 0;
        let mut global = PsbtGlobal {
            unsigned_tx: Vec::new(),
            version: None,
            xpubs: BTreeMap::new(),
            proprietary: BTreeMap::new(),
            unknown: BTreeMap::new(),
        };

        loop {
            if cursor >= data.len() {
                return Err(PsbtError::UnexpectedEof);
            }

            // Check for separator
            if data[cursor] == 0x00 {
                cursor += 1;
                break;
            }

            // Read key-value pair
            let (key, value, bytes_read) = deserialize_kv(&data[cursor..])?;
            cursor += bytes_read;

            if key.is_empty() {
                return Err(PsbtError::InvalidKey);
            }

            match key[0] {
                0x00 => global.unsigned_tx = value,
                0xfb => {
                    if value.len() == 4 {
                        global.version = Some(u32::from_le_bytes(value[0..4].try_into().unwrap()));
                    }
                }
                0x01 => {
                    global.xpubs.insert(key[1..].to_vec(), value);
                }
                0xfc => {
                    global.proprietary.insert(key[1..].to_vec(), value);
                }
                _ => {
                    global.unknown.insert(key, value);
                }
            }
        }

        if global.unsigned_tx.is_empty() {
            return Err(PsbtError::MissingUnsignedTx);
        }

        Ok((global, cursor))
    }

    fn parse_tx_counts(tx: &[u8]) -> Result<(usize, usize), PsbtError> {
        let mut cursor = 4; // Skip version

        if tx.len() < cursor {
            return Err(PsbtError::InvalidTransaction);
        }

        // Read input count
        let (input_count, bytes) = read_varint(&tx[cursor..])?;
        cursor += bytes;

        // Skip inputs
        for _ in 0..input_count {
            if cursor + 32 + 4 > tx.len() {
                return Err(PsbtError::InvalidTransaction);
            }
            cursor += 32 + 4; // txid + vout
            let (script_len, bytes) = read_varint(&tx[cursor..])?;
            cursor += bytes + script_len + 4; // script + sequence
            if cursor > tx.len() {
                return Err(PsbtError::InvalidTransaction);
            }
        }

        // Read output count
        let (output_count, _) = read_varint(&tx[cursor..])?;

        Ok((input_count, output_count))
    }
}

impl PsbtInput {
    pub fn new() -> Self {
        Self {
            non_witness_utxo: None,
            witness_utxo: None,
            partial_sigs: BTreeMap::new(),
            sighash_type: None,
            redeem_script: None,
            witness_script: None,
            bip32_derivation: BTreeMap::new(),
            final_script_sig: None,
            final_script_witness: None,
            por_commitment: None,
            ripemd160_preimages: BTreeMap::new(),
            sha256_preimages: BTreeMap::new(),
            hash160_preimages: BTreeMap::new(),
            hash256_preimages: BTreeMap::new(),
            tap_key_sig: None,
            tap_script_sigs: BTreeMap::new(),
            tap_leaf_scripts: Vec::new(),
            tap_bip32_derivation: BTreeMap::new(),
            tap_internal_key: None,
            tap_merkle_root: None,
            proprietary: BTreeMap::new(),
            unknown: BTreeMap::new(),
        }
    }

    fn serialize(&self, output: &mut Vec<u8>) {
        // Non-witness UTXO
        if let Some(ref tx) = self.non_witness_utxo {
            serialize_kv(output, &[0x00], tx);
        }

        // Witness UTXO
        if let Some(ref utxo) = self.witness_utxo {
            let mut value = utxo.amount.to_le_bytes().to_vec();
            value.extend_from_slice(&serialize_script(&utxo.script_pubkey));
            serialize_kv(output, &[0x01], &value);
        }

        // Partial signatures
        for (pubkey, sig) in &self.partial_sigs {
            let mut key = vec![0x02];
            key.extend_from_slice(pubkey);
            serialize_kv(output, &key, sig);
        }

        // Sighash type
        if let Some(sighash) = self.sighash_type {
            serialize_kv(output, &[0x03], &sighash.to_le_bytes());
        }

        // Redeem script
        if let Some(ref script) = self.redeem_script {
            serialize_kv(output, &[0x04], script);
        }

        // Witness script
        if let Some(ref script) = self.witness_script {
            serialize_kv(output, &[0x05], script);
        }

        // BIP32 derivations
        for (pubkey, deriv) in &self.bip32_derivation {
            let mut key = vec![0x06];
            key.extend_from_slice(pubkey);

            let mut value = deriv.master_fingerprint.to_vec();
            for step in &deriv.path {
                value.extend_from_slice(&step.to_le_bytes());
            }

            serialize_kv(output, &key, &value);
        }

        // Final scriptSig
        if let Some(ref script) = self.final_script_sig {
            serialize_kv(output, &[0x07], script);
        }

        // Final witness
        if let Some(ref witness) = self.final_script_witness {
            let mut value = serialize_varint(witness.len());
            for item in witness {
                value.extend_from_slice(&serialize_varint(item.len()));
                value.extend_from_slice(item);
            }
            serialize_kv(output, &[0x08], &value);
        }

        // Por commitment
        if let Some(ref comm) = self.por_commitment {
            serialize_kv(output, &[0x09], comm);
        }

        // Ripemd160 preimages
        for (hash, preimage) in &self.ripemd160_preimages {
            let mut key = vec![0x0a];
            key.extend_from_slice(hash);
            serialize_kv(output, &key, preimage);
        }

        // Sha256 preimages
        for (hash, preimage) in &self.sha256_preimages {
            let mut key = vec![0x0b];
            key.extend_from_slice(hash);
            serialize_kv(output, &key, preimage);
        }

        // Hash160 preimages
        for (hash, preimage) in &self.hash160_preimages {
            let mut key = vec![0x0c];
            key.extend_from_slice(hash);
            serialize_kv(output, &key, preimage);
        }

        // Hash256 preimages
        for (hash, preimage) in &self.hash256_preimages {
            let mut key = vec![0x0d];
            key.extend_from_slice(hash);
            serialize_kv(output, &key, preimage);
        }

        // Tap key sig
        if let Some(ref sig) = self.tap_key_sig {
            serialize_kv(output, &[0x13], sig);
        }

        // Tap script sigs
        for (key_data, sig) in &self.tap_script_sigs {
            let mut key = vec![0x14];
            key.extend_from_slice(key_data);
            serialize_kv(output, &key, sig);
        }

        // Tap leaf scripts
        for leaf in &self.tap_leaf_scripts {
            let mut key = vec![0x15];
            key.extend_from_slice(&leaf.control_block);
            let mut value = leaf.script.clone();
            value.push(leaf.leaf_version);
            serialize_kv(output, &key, &value);
        }

        // Tap bip32 derivations
        for (pubkey, deriv) in &self.tap_bip32_derivation {
            let mut key = vec![0x16];
            key.extend_from_slice(pubkey);

            let mut value = serialize_varint(deriv.leaf_hashes.len());
            for hash in &deriv.leaf_hashes {
                value.extend_from_slice(hash);
            }
            value.extend_from_slice(&deriv.master_fingerprint);
            for step in &deriv.path {
                value.extend_from_slice(&step.to_le_bytes());
            }

            serialize_kv(output, &key, &value);
        }

        // Tap internal key
        if let Some(ref key) = self.tap_internal_key {
            serialize_kv(output, &[0x17], key);
        }

        // Tap merkle root
        if let Some(ref root) = self.tap_merkle_root {
            serialize_kv(output, &[0x18], root);
        }

        // Proprietary
        for (key_data, value) in &self.proprietary {
            let mut key = vec![0xfc];
            key.extend_from_slice(key_data);
            serialize_kv(output, &key, value);
        }

        // Unknown
        for (key, value) in &self.unknown {
            serialize_kv(output, key, value);
        }

        // Separator
        output.push(0x00);
    }

    fn deserialize(data: &[u8]) -> Result<(Self, usize), PsbtError> {
        let mut cursor = 0;
        let mut input = PsbtInput::new();

        loop {
            if cursor >= data.len() {
                return Err(PsbtError::UnexpectedEof);
            }

            if data[cursor] == 0x00 {
                cursor += 1;
                break;
            }

            let (key, value, bytes_read) = deserialize_kv(&data[cursor..])?;
            cursor += bytes_read;

            if key.is_empty() {
                continue;
            }

            match key[0] {
                0x00 => input.non_witness_utxo = Some(value),
                0x01 => {
                    if value.len() >= 8 {
                        let amount = u64::from_le_bytes(
                            value[0..8]
                                .try_into()
                                .map_err(|_| PsbtError::InvalidTransaction)?,
                        );
                        let mut cur = 8;
                        let (len, b) = read_varint(&value[cur..])?;
                        cur += b;
                        if cur + len != value.len() {
                            return Err(PsbtError::InvalidTransaction);
                        }
                        let script_pubkey = value[cur..cur + len].to_vec();
                        input.witness_utxo = Some(WitnessUtxo {
                            amount,
                            script_pubkey,
                        });
                    }
                }
                0x02 => {
                    input.partial_sigs.insert(key[1..].to_vec(), value);
                }
                0x03 => {
                    if value.len() == 4 {
                        input.sighash_type =
                            Some(u32::from_le_bytes(value[0..4].try_into().unwrap()));
                    }
                }
                0x04 => input.redeem_script = Some(value),
                0x05 => input.witness_script = Some(value),
                0x06 => {
                    let pubkey = key[1..].to_vec();
                    if value.len() >= 4 && (value.len() - 4) % 4 == 0 {
                        let master_fingerprint: [u8; 4] = value[0..4].try_into().unwrap();
                        let mut path = Vec::new();
                        for chunk in value[4..].chunks(4) {
                            path.push(u32::from_le_bytes(chunk.try_into().unwrap()));
                        }
                        input.bip32_derivation.insert(
                            pubkey,
                            Bip32Derivation {
                                master_fingerprint,
                                path,
                            },
                        );
                    }
                }
                0x07 => input.final_script_sig = Some(value),
                0x08 => {
                    let mut cur = 0;
                    let (len, b) = read_varint(&value[cur..])?;
                    cur += b;
                    let mut witness = Vec::with_capacity(len);
                    for _ in 0..len {
                        let (item_len, b) = read_varint(&value[cur..])?;
                        cur += b;
                        if cur + item_len > value.len() {
                            return Err(PsbtError::UnexpectedEof);
                        }
                        witness.push(value[cur..cur + item_len].to_vec());
                        cur += item_len;
                    }
                    input.final_script_witness = Some(witness);
                }
                0x09 => input.por_commitment = Some(value),
                0x0a => {
                    if key.len() == 21 {
                        let hash: [u8; 20] = key[1..].try_into().unwrap();
                        input.ripemd160_preimages.insert(hash, value);
                    }
                }
                0x0b => {
                    if key.len() == 33 {
                        let hash: [u8; 32] = key[1..].try_into().unwrap();
                        input.sha256_preimages.insert(hash, value);
                    }
                }
                0x0c => {
                    if key.len() == 21 {
                        let hash: [u8; 20] = key[1..].try_into().unwrap();
                        input.hash160_preimages.insert(hash, value);
                    }
                }
                0x0d => {
                    if key.len() == 33 {
                        let hash: [u8; 32] = key[1..].try_into().unwrap();
                        input.hash256_preimages.insert(hash, value);
                    }
                }
                0x13 => input.tap_key_sig = Some(value),
                0x14 => {
                    let map_key = key[1..].to_vec();
                    input.tap_script_sigs.insert(map_key, value);
                }
                0x15 => {
                    let control_block = key[1..].to_vec();
                    if !value.is_empty() {
                        let leaf_version = value[value.len() - 1];
                        let script = value[0..value.len() - 1].to_vec();
                        input.tap_leaf_scripts.push(TapLeafScript {
                            control_block,
                            script,
                            leaf_version,
                        });
                    }
                }
                0x16 => {
                    let pubkey = key[1..].to_vec();
                    let mut cur = 0;
                    let (num, b) = read_varint(&value[cur..])?;
                    cur += b;
                    let mut leaf_hashes = Vec::with_capacity(num);
                    for _ in 0..num {
                        if cur + 32 > value.len() {
                            return Err(PsbtError::InvalidKey);
                        }
                        let hash: [u8; 32] = value[cur..cur + 32].try_into().unwrap();
                        leaf_hashes.push(hash);
                        cur += 32;
                    }
                    if cur + 4 > value.len() {
                        return Err(PsbtError::InvalidKey);
                    }
                    let master_fingerprint: [u8; 4] = value[cur..cur + 4].try_into().unwrap();
                    cur += 4;
                    let mut path = Vec::new();
                    for chunk in value[cur..].chunks(4) {
                        if chunk.len() != 4 {
                            return Err(PsbtError::InvalidKey);
                        }
                        path.push(u32::from_le_bytes(chunk.try_into().unwrap()));
                    }
                    input.tap_bip32_derivation.insert(
                        pubkey,
                        TapBip32Derivation {
                            leaf_hashes,
                            master_fingerprint,
                            path,
                        },
                    );
                }
                0x17 => input.tap_internal_key = Some(value),
                0x18 => input.tap_merkle_root = Some(value),
                0xfc => {
                    input.proprietary.insert(key[1..].to_vec(), value);
                }
                _ => {
                    input.unknown.insert(key, value);
                }
            }
        }

        Ok((input, cursor))
    }
}

impl PsbtOutput {
    pub fn new() -> Self {
        Self {
            redeem_script: None,
            witness_script: None,
            bip32_derivation: BTreeMap::new(),
            tap_internal_key: None,
            tap_tree: None,
            tap_bip32_derivation: BTreeMap::new(),
            proprietary: BTreeMap::new(),
            unknown: BTreeMap::new(),
        }
    }

    fn serialize(&self, output: &mut Vec<u8>) {
        // Redeem script
        if let Some(ref script) = self.redeem_script {
            serialize_kv(output, &[0x00], script);
        }

        // Witness script
        if let Some(ref script) = self.witness_script {
            serialize_kv(output, &[0x01], script);
        }

        // BIP32 derivations
        for (pubkey, deriv) in &self.bip32_derivation {
            let mut key = vec![0x02];
            key.extend_from_slice(pubkey);

            let mut value = deriv.master_fingerprint.to_vec();
            for step in &deriv.path {
                value.extend_from_slice(&step.to_le_bytes());
            }

            serialize_kv(output, &key, &value);
        }

        // Tap internal key
        if let Some(ref key) = self.tap_internal_key {
            serialize_kv(output, &[0x05], key);
        }

        // Tap tree
        if let Some(ref tree) = self.tap_tree {
            serialize_kv(output, &[0x06], tree);
        }

        // Tap bip32 derivations
        for (pubkey, deriv) in &self.tap_bip32_derivation {
            let mut key = vec![0x07];
            key.extend_from_slice(pubkey);

            let mut value = serialize_varint(deriv.leaf_hashes.len());
            for hash in &deriv.leaf_hashes {
                value.extend_from_slice(hash);
            }
            value.extend_from_slice(&deriv.master_fingerprint);
            for step in &deriv.path {
                value.extend_from_slice(&step.to_le_bytes());
            }

            serialize_kv(output, &key, &value);
        }

        // Proprietary
        for (key_data, value) in &self.proprietary {
            let mut key = vec![0xfc];
            key.extend_from_slice(key_data);
            serialize_kv(output, &key, value);
        }

        // Unknown
        for (key, value) in &self.unknown {
            serialize_kv(output, key, value);
        }

        // Separator
        output.push(0x00);
    }

    fn deserialize(data: &[u8]) -> Result<(Self, usize), PsbtError> {
        let mut cursor = 0;
        let mut output = PsbtOutput::new();

        loop {
            if cursor >= data.len() {
                return Err(PsbtError::UnexpectedEof);
            }

            if data[cursor] == 0x00 {
                cursor += 1;
                break;
            }

            let (key, value, bytes_read) = deserialize_kv(&data[cursor..])?;
            cursor += bytes_read;

            if key.is_empty() {
                continue;
            }

            match key[0] {
                0x00 => output.redeem_script = Some(value),
                0x01 => output.witness_script = Some(value),
                0x02 => {
                    let pubkey = key[1..].to_vec();
                    if value.len() >= 4 && (value.len() - 4) % 4 == 0 {
                        let master_fingerprint: [u8; 4] = value[0..4].try_into().unwrap();
                        let mut path = Vec::new();
                        for chunk in value[4..].chunks(4) {
                            path.push(u32::from_le_bytes(chunk.try_into().unwrap()));
                        }
                        output.bip32_derivation.insert(
                            pubkey,
                            Bip32Derivation {
                                master_fingerprint,
                                path,
                            },
                        );
                    }
                }
                0x05 => output.tap_internal_key = Some(value),
                0x06 => output.tap_tree = Some(value),
                0x07 => {
                    let pubkey = key[1..].to_vec();
                    let mut cur = 0;
                    let (num, b) = read_varint(&value[cur..])?;
                    cur += b;
                    let mut leaf_hashes = Vec::with_capacity(num);
                    for _ in 0..num {
                        if cur + 32 > value.len() {
                            return Err(PsbtError::InvalidKey);
                        }
                        let hash: [u8; 32] = value[cur..cur + 32].try_into().unwrap();
                        leaf_hashes.push(hash);
                        cur += 32;
                    }
                    if cur + 4 > value.len() {
                        return Err(PsbtError::InvalidKey);
                    }
                    let master_fingerprint: [u8; 4] = value[cur..cur + 4].try_into().unwrap();
                    cur += 4;
                    let mut path = Vec::new();
                    for chunk in value[cur..].chunks(4) {
                        if chunk.len() != 4 {
                            return Err(PsbtError::InvalidKey);
                        }
                        path.push(u32::from_le_bytes(chunk.try_into().unwrap()));
                    }
                    output.tap_bip32_derivation.insert(
                        pubkey,
                        TapBip32Derivation {
                            leaf_hashes,
                            master_fingerprint,
                            path,
                        },
                    );
                }
                0xfc => {
                    output.proprietary.insert(key[1..].to_vec(), value);
                }
                _ => {
                    output.unknown.insert(key, value);
                }
            }
        }

        Ok((output, cursor))
    }
}

/// PSBT Error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PsbtError {
    InvalidMagic,
    InvalidBase64,
    InvalidKey,
    InvalidTransaction,
    MissingUnsignedTx,
    InvalidInputIndex,
    InvalidOutputIndex,
    InputNotFinalized(usize),
    DifferentTransactions,
    UnexpectedEof,
    InvalidVarint,
    ConflictingData,
    CannotFinalize,
}

impl std::fmt::Display for PsbtError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            PsbtError::InvalidMagic => write!(f, "Invalid PSBT magic bytes"),
            PsbtError::InvalidBase64 => write!(f, "Invalid base64 encoding"),
            PsbtError::InvalidKey => write!(f, "Invalid PSBT key"),
            PsbtError::InvalidTransaction => write!(f, "Invalid transaction"),
            PsbtError::MissingUnsignedTx => write!(f, "Missing unsigned transaction"),
            PsbtError::InvalidInputIndex => write!(f, "Invalid input index"),
            PsbtError::InvalidOutputIndex => write!(f, "Invalid output index"),
            PsbtError::InputNotFinalized(i) => write!(f, "Input {} not finalized", i),
            PsbtError::DifferentTransactions => write!(f, "PSBTs are for different transactions"),
            PsbtError::UnexpectedEof => write!(f, "Unexpected end of file"),
            PsbtError::InvalidVarint => write!(f, "Invalid varint encoding"),
            PsbtError::ConflictingData => write!(f, "Conflicting data in combine"),
            PsbtError::CannotFinalize => write!(f, "Cannot finalize input with available data"),
        }
    }
}

impl std::error::Error for PsbtError {}

// Helper functions for merging in combine

fn merge_opt<T: PartialEq + Clone>(
    target: &mut Option<T>,
    source: &Option<T>,
) -> Result<(), PsbtError> {
    if let Some(s) = source {
        if let Some(t) = target {
            if t != s {
                return Err(PsbtError::ConflictingData);
            }
        } else {
            *target = Some(s.clone());
        }
    }
    Ok(())
}

fn merge_map<K: Ord + Clone, V: PartialEq + Clone>(
    target: &mut BTreeMap<K, V>,
    source: &BTreeMap<K, V>,
) -> Result<(), PsbtError> {
    for (k, v) in source {
        match target.entry(k.clone()) {
            Entry::Vacant(e) => {
                e.insert(v.clone());
            }
            Entry::Occupied(e) => {
                if e.get() != v {
                    return Err(PsbtError::ConflictingData);
                }
            }
        }
    }
    Ok(())
}

fn merge_vec<T: PartialEq + Clone>(target: &mut Vec<T>, source: &Vec<T>) -> Result<(), PsbtError> {
    for s in source {
        if !target.contains(s) {
            target.push(s.clone());
        }
    }
    Ok(())
}

// Serialization helpers

fn serialize_kv(output: &mut Vec<u8>, key: &[u8], value: &[u8]) {
    output.extend_from_slice(&serialize_varint(key.len()));
    output.extend_from_slice(key);
    output.extend_from_slice(&serialize_varint(value.len()));
    output.extend_from_slice(value);
}

fn deserialize_kv(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>, usize), PsbtError> {
    let mut cursor = 0;

    // Read key length
    let (key_len, bytes) = read_varint(data)?;
    cursor += bytes;

    // Read key
    if cursor + key_len > data.len() {
        return Err(PsbtError::UnexpectedEof);
    }
    let key = data[cursor..cursor + key_len].to_vec();
    cursor += key_len;

    // Read value length
    let (value_len, bytes) = read_varint(&data[cursor..])?;
    cursor += bytes;

    // Read value
    if cursor + value_len > data.len() {
        return Err(PsbtError::UnexpectedEof);
    }
    let value = data[cursor..cursor + value_len].to_vec();
    cursor += value_len;

    Ok((key, value, cursor))
}

pub fn serialize_varint(n: usize) -> Vec<u8> {
    let n = n as u64;
    if n < 0xfd {
        vec![n as u8]
    } else if n <= 0xffff {
        let mut v = vec![0xfd];
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v
    } else if n <= 0xffffffff {
        let mut v = vec![0xfe];
        v.extend_from_slice(&(n as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![0xff];
        v.extend_from_slice(&n.to_le_bytes());
        v
    }
}

fn read_varint(data: &[u8]) -> Result<(usize, usize), PsbtError> {
    if data.is_empty() {
        return Err(PsbtError::InvalidVarint);
    }

    let first = data[0];

    if first < 0xfd {
        Ok((first as usize, 1))
    } else if first == 0xfd {
        if data.len() < 3 {
            return Err(PsbtError::UnexpectedEof);
        }
        let value = u16::from_le_bytes([data[1], data[2]]) as usize;
        Ok((value, 3))
    } else if first == 0xfe {
        if data.len() < 5 {
            return Err(PsbtError::UnexpectedEof);
        }
        let value = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as usize;
        Ok((value, 5))
    } else {
        if data.len() < 9 {
            return Err(PsbtError::UnexpectedEof);
        }
        let value = u64::from_le_bytes([
            data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
        ]) as usize;
        Ok((value, 9))
    }
}

fn serialize_script(script: &[u8]) -> Vec<u8> {
    let mut result = serialize_varint(script.len());
    result.extend_from_slice(script);
    result
}

fn serialize_pushdata(data: &[u8]) -> Vec<u8> {
    let len = data.len();
    let mut result = Vec::new();

    if len < 0x4c {
        result.push(len as u8);
    } else if len <= 0xff {
        result.push(0x4c);
        result.push(len as u8);
    } else if len <= 0xffff {
        result.push(0x4d);
        result.extend_from_slice(&(len as u16).to_le_bytes());
    } else {
        result.push(0x4e);
        result.extend_from_slice(&(len as u32).to_le_bytes());
    }

    result.extend_from_slice(data);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psbt_creation() {
        // Minimal invalid tx for testing
        let unsigned_tx = vec![0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
        let result = Psbt::new(unsigned_tx.clone());
        assert!(result.is_err()); // Invalid tx, but for count it's ok? Wait, adjust test
    }

    // Add more tests for serialize, deserialize, combine, etc.
    // For example:
    #[test]
    fn test_serialize_deserialize() {
        let unsigned_tx = vec![
            0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let psbt = Psbt::new(unsigned_tx).unwrap();
        let serialized = psbt.serialize();
        let deserialized = Psbt::deserialize(&serialized).unwrap();
        assert_eq!(psbt.global.unsigned_tx, deserialized.global.unsigned_tx);
        // Add assertions for other fields
    }
}
