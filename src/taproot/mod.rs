//! Taproot (P2TR) transaction support
//!
//! Implements BIP340 (Schnorr signatures), BIP341 (Taproot), and BIP342 (Tapscript)

pub mod p2tr;
pub mod schnorr;
pub mod taptree;

pub use p2tr::*;
pub use schnorr::*;
pub use taptree::*;
