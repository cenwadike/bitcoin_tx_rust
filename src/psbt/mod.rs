//! PSBT (Partially Signed Bitcoin Transactions) Module
//!
//! Implements BIP-174 and BIP-370 (PSBT Version 2) for creating, signing,
//! combining, and finalizing partially signed Bitcoin transactions.

pub mod psbt;

pub use psbt::*;
