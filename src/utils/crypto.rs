use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// Compute SHA256 hash
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute double SHA256 (hash256)
pub fn hash256(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// Compute RIPEMD160(SHA256(data)) - also known as hash160
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = sha256(data);
    let mut hasher = Ripemd160::new();
    hasher.update(&sha);
    hasher.finalize().into()
}

/// Encode a variable length integer (varint)
pub fn varint_len(data: &[u8]) -> Vec<u8> {
    let len = data.len();
    if len < 0xfd {
        vec![len as u8]
    } else if len <= 0xffff {
        let mut v = vec![0xfd];
        v.extend_from_slice(&(len as u16).to_le_bytes());
        v
    } else if len <= 0xffffffff {
        let mut v = vec![0xfe];
        v.extend_from_slice(&(len as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![0xff];
        v.extend_from_slice(&(len as u64).to_le_bytes());
        v
    }
}

// Encode a variable length integer (varint) for u64
pub fn varint_encode(n: u64) -> Vec<u8> {
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

/// Create a push bytes operation with length prefix
pub fn pushbytes(data: &[u8]) -> Vec<u8> {
    let mut result = varint_len(data);
    result.extend_from_slice(data);
    result
}

/// Compute a BIP-341 style tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)
pub fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_bytes = tag.as_bytes();
    let tag_hash = Sha256::digest(tag_bytes);

    let mut hasher = Sha256::new();
    hasher.update(&tag_hash);
    hasher.update(&tag_hash); // double SHA256(tag)
    hasher.update(data);

    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash256() {
        let data = b"hello world";
        let result = hash256(data);
        assert_eq!(result.len(), 32);

        // Test with known vector
        let data = hex::decode("00").unwrap();
        let result = hash256(&data);
        let expected = "1406e05881e299367766d313e26c05564ec91bf721d31726bd6e46e60689539a";
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    fn test_hash160() {
        let data = b"hello world";
        let result = hash160(data);
        assert_eq!(result.len(), 20);
    }

    #[test]
    fn test_varint_small() {
        assert_eq!(varint_len(&vec![0u8; 10]), vec![10]);
        assert_eq!(varint_len(&vec![0u8; 252]), vec![252]);
    }

    #[test]
    fn test_varint_medium() {
        let data = vec![0u8; 300];
        let varint = varint_len(&data);
        assert_eq!(varint[0], 0xfd);
        assert_eq!(u16::from_le_bytes([varint[1], varint[2]]), 300);
    }

    #[test]
    fn test_varint_large() {
        let data = vec![0u8; 70000];
        let varint = varint_len(&data);
        assert_eq!(varint[0], 0xfe);
    }

    #[test]
    fn test_pushbytes() {
        let data = vec![0x42u8; 10];
        let result = pushbytes(&data);
        assert_eq!(result[0], 10); // Length byte
        assert_eq!(result.len(), 11); // Length + data
    }
}
