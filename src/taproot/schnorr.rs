//! BIP340 Schnorr Signature Implementation

use crate::crypto::tagged_hash;
use secp256k1::Parity;
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, Message, Scalar, Secp256k1, XOnlyPublicKey};

/// Generate x-only public key from private key (BIP340)
/// Returns 32-byte x-only pubkey (even y-coordinate)
pub fn schnorr_pubkey_gen(privkey: &[u8; 32]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_seckey_slice(&secp, privkey)?;
    let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
    Ok(xonly.serialize().to_vec())
}

/// Sign a message hash using Schnorr signature (BIP340)
pub fn schnorr_sign(
    privkey: &[u8; 32],
    msg_hash: &[u8; 32],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_seckey_slice(&secp, privkey)?;
    let message = Message::from_digest_slice(msg_hash)?;
    let sig = secp.sign_schnorr(&message, &keypair);
    Ok(sig.as_ref().to_vec())
}

/// Verify Schnorr signature (BIP340)
pub fn schnorr_verify(
    pubkey: &[u8],
    msg_hash: &[u8; 32],
    signature: &[u8],
) -> Result<bool, Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let xonly_pubkey = XOnlyPublicKey::from_slice(pubkey)?;
    let message = Message::from_digest_slice(msg_hash)?;
    let sig = Signature::from_slice(signature)?;

    Ok(secp.verify_schnorr(&sig, &message, &xonly_pubkey).is_ok())
}

/// Compute taptweak for a public key (BIP341)
/// taptweak = tagged_hash("TapTweak", pubkey || merkle_root)
pub fn compute_taptweak(internal_pubkey: &[u8], merkle_root: Option<&[u8]>) -> [u8; 32] {
    let mut data = internal_pubkey.to_vec();
    if let Some(root) = merkle_root {
        data.extend_from_slice(root);
    }
    tagged_hash("TapTweak", &data)
}

/// Tweak a public key with taptweak (BIP341)
/// Returns (negated, tweaked_pubkey) where negated = true if the raw tweaked point had odd Y
/// (i.e., if normalization flipped it)
pub fn taproot_tweak_pubkey(
    internal_pubkey: &[u8],
    merkle_root: Option<&[u8]>,
) -> Result<(bool, Vec<u8>), Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let internal_key = XOnlyPublicKey::from_slice(internal_pubkey)?;

    let tweak_bytes = compute_taptweak(internal_pubkey, merkle_root);
    let tweak_scalar = Scalar::from_be_bytes(tweak_bytes)?;

    // add_tweak returns (even-Y xonly key, raw parity before normalization)
    let (tweaked_key, raw_parity) = internal_key.add_tweak(&secp, &tweak_scalar)?;

    let negated = raw_parity == Parity::Odd;

    Ok((negated, tweaked_key.serialize().to_vec()))
}

/// Tweak a private key with taptweak (BIP341)
/// Returns the tweaked private key that corresponds exactly to the even-Y output pubkey
pub fn taproot_tweak_privkey(
    internal_privkey: &[u8; 32],
    merkle_root: Option<&[u8]>,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();

    // Load the original secret key
    let mut secret_key = secp256k1::SecretKey::from_slice(internal_privkey)?;

    // Normalize to match the even-Y internal pubkey (used for tweak hash)
    let (_, parity) = secret_key.x_only_public_key(&secp);
    if parity == Parity::Odd {
        secret_key = secret_key.negate();
    }

    // Now derive the even-Y internal pubkey for the tweak computation
    let (internal_pubkey, _) = secret_key.x_only_public_key(&secp);

    // Compute taptweak using the correct (even-Y) pubkey bytes
    let tweak_bytes = compute_taptweak(&internal_pubkey.serialize(), merkle_root);
    let tweak_scalar = Scalar::from_be_bytes(tweak_bytes)?;

    // Add the tweak
    let tweaked_secret = secret_key.add_tweak(&tweak_scalar)?;

    // The resulting private key now corresponds exactly to the even-Y tweaked pubkey
    Ok(tweaked_secret.secret_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schnorr_pubkey_gen() {
        let privkey = [0x01u8; 32];
        let pubkey = schnorr_pubkey_gen(&privkey).unwrap();
        assert_eq!(pubkey.len(), 32); // x-only pubkey
    }

    #[test]
    fn test_schnorr_sign_verify() {
        let privkey = [0x01u8; 32];
        let pubkey = schnorr_pubkey_gen(&privkey).unwrap();
        let msg_hash = [0x42u8; 32];

        let signature = schnorr_sign(&privkey, &msg_hash).unwrap();
        assert_eq!(signature.len(), 64); // Schnorr signature is 64 bytes

        let valid = schnorr_verify(&pubkey, &msg_hash, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_taptweak_computation() {
        let internal_pubkey = [0x02u8; 32];
        let merkle_root = [0x03u8; 32];

        let tweak = compute_taptweak(&internal_pubkey, Some(&merkle_root));
        assert_eq!(tweak.len(), 32);
    }

    #[test]
    fn test_taproot_key_tweak() {
        let internal_privkey = [0x01u8; 32];
        let internal_pubkey = schnorr_pubkey_gen(&internal_privkey).unwrap();

        let merkle_root = [0x02u8; 32];

        // Tweak pubkey
        let (_, tweaked_pubkey) =
            taproot_tweak_pubkey(&internal_pubkey, Some(&merkle_root)).unwrap();
        assert_eq!(tweaked_pubkey.len(), 32);

        // Tweak privkey
        let tweaked_privkey = taproot_tweak_privkey(&internal_privkey, Some(&merkle_root)).unwrap();

        // Verify tweaked privkey corresponds to tweaked pubkey
        let pubkey_from_tweaked = schnorr_pubkey_gen(&tweaked_privkey).unwrap();
        assert_eq!(pubkey_from_tweaked, tweaked_pubkey);
    }
}
