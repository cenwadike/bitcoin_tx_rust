use rand::rngs::OsRng;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, ecdsa::Signature};

/// Generate a new private key
pub fn generate_privkey() -> [u8; 32] {
    let secp = Secp256k1::new();
    let (secret_key, _) = secp.generate_keypair(&mut OsRng);
    secret_key.secret_bytes()
}

/// Derive public key from private key
pub fn privkey_to_pubkey(privkey: &[u8; 32]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(privkey)?;
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    Ok(public_key.serialize().to_vec())
}

/// Sign a message hash with a private key
pub fn sign_hash(
    privkey: &[u8; 32],
    hash: &[u8; 32],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(privkey)?;
    let message = Message::from_digest_slice(hash)?;
    let signature = secp.sign_ecdsa(&message, &secret_key);
    Ok(signature.serialize_der().to_vec())
}

/// Verify a signature
pub fn verify_signature(
    pubkey: &[u8],
    hash: &[u8; 32],
    signature: &[u8],
) -> Result<bool, Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let public_key = PublicKey::from_slice(pubkey)?;
    let message = Message::from_digest_slice(hash)?;
    let sig = Signature::from_der(signature)?;

    Ok(secp.verify_ecdsa(&message, &sig, &public_key).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let privkey = generate_privkey();
        assert_eq!(privkey.len(), 32);

        let pubkey = privkey_to_pubkey(&privkey).unwrap();
        assert_eq!(pubkey.len(), 33); // Compressed pubkey
        assert!(pubkey[0] == 0x02 || pubkey[0] == 0x03);
    }

    #[test]
    fn test_deterministic_pubkey() {
        let privkey = [0x11u8; 32];
        let pubkey = privkey_to_pubkey(&privkey).unwrap();

        // Should always produce the same pubkey for same privkey
        let pubkey2 = privkey_to_pubkey(&privkey).unwrap();
        assert_eq!(pubkey, pubkey2);

        // Check expected value
        let expected = "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
        assert_eq!(hex::encode(&pubkey), expected);
    }

    #[test]
    fn test_sign_and_verify() {
        let privkey = generate_privkey();
        let pubkey = privkey_to_pubkey(&privkey).unwrap();
        let hash = [0x42u8; 32];

        let signature = sign_hash(&privkey, &hash).unwrap();
        let valid = verify_signature(&pubkey, &hash, &signature).unwrap();

        assert!(valid);
        assert!(signature.len() >= 70 && signature.len() <= 73); // DER signature size
    }

    #[test]
    fn test_invalid_signature() {
        let privkey1 = [0x11u8; 32];
        let privkey2 = [0x22u8; 32];

        let pubkey1 = privkey_to_pubkey(&privkey1).unwrap();
        let hash = [0x42u8; 32];

        let signature = sign_hash(&privkey2, &hash).unwrap();
        let valid = verify_signature(&pubkey1, &hash, &signature).unwrap();

        assert!(!valid); // Should fail - wrong key
    }

    #[test]
    fn test_multiple_keys() {
        let privkey1 = [0x11u8; 32];
        let privkey2 = [0x22u8; 32];

        let pubkey1 = privkey_to_pubkey(&privkey1).unwrap();
        let pubkey2 = privkey_to_pubkey(&privkey2).unwrap();

        assert_ne!(pubkey1, pubkey2);
    }
}
