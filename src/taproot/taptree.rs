//! TapTree implementation for Taproot script commitments

use crate::{crypto::tagged_hash, utils::*};

const TAPSCRIPT_VER: u8 = 0xc0;

/// Represents a TapLeaf (script in the taptree)
#[derive(Debug, Clone)]
pub struct TapLeaf {
    pub script: Vec<u8>,
    pub version: u8,
}

impl TapLeaf {
    pub fn new(script: Vec<u8>) -> Self {
        Self {
            script,
            version: TAPSCRIPT_VER,
        }
    }

    /// Compute the tagged hash of this leaf
    pub fn leaf_hash(&self) -> [u8; 32] {
        let mut data = vec![self.version];
        data.extend_from_slice(&pushbytes(&self.script));
        tagged_hash("TapLeaf", &data)
    }
}

/// Represents a node in the TapTree (either leaf or branch)
#[derive(Debug, Clone)]
pub enum TapNode {
    Leaf(TapLeaf),
    Branch(Box<TapNode>, Box<TapNode>),
}

impl TapNode {
    /// Compute the hash of this node
    pub fn node_hash(&self) -> [u8; 32] {
        match self {
            TapNode::Leaf(leaf) => leaf.leaf_hash(),
            TapNode::Branch(left, right) => tapbranch_hash(&left.node_hash(), &right.node_hash()),
        }
    }

    /// Get the merkle root of this tree
    pub fn merkle_root(&self) -> [u8; 32] {
        self.node_hash()
    }
}

/// Compute TapBranch hash (BIP341)
/// Child hashes are lexicographically sorted before concatenation
pub fn tapbranch_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let (first, second) = if left < right {
        (left, right)
    } else {
        (right, left)
    };

    let mut data = Vec::new();
    data.extend_from_slice(first);
    data.extend_from_slice(second);

    tagged_hash("TapBranch", &data)
}

/// Create a simple 2-leaf taptree
pub fn create_2leaf_taptree(leaf1: TapLeaf, leaf2: TapLeaf) -> TapNode {
    TapNode::Branch(
        Box::new(TapNode::Leaf(leaf1)),
        Box::new(TapNode::Leaf(leaf2)),
    )
}

/// Create a 3-leaf taptree (balanced)
pub fn create_3leaf_taptree(leaf1: TapLeaf, leaf2: TapLeaf, leaf3: TapLeaf) -> TapNode {
    let branch_ab = TapNode::Branch(
        Box::new(TapNode::Leaf(leaf1)),
        Box::new(TapNode::Leaf(leaf2)),
    );

    TapNode::Branch(Box::new(branch_ab), Box::new(TapNode::Leaf(leaf3)))
}

/// Compute control block for script path spend
/// control_block = leaf_version_with_parity || internal_pubkey || merkle_proof
pub fn compute_control_block(
    internal_pubkey: &[u8],
    merkle_path: &[[u8; 32]],
    parity: bool,
    leaf_version: u8,
) -> Vec<u8> {
    let version_byte = leaf_version | if parity { 1 } else { 0 };

    let mut control_block = vec![version_byte];
    control_block.extend_from_slice(internal_pubkey);
    for hash in merkle_path {
        control_block.extend_from_slice(hash);
    }

    control_block
}

/// Helper to create pay-to-pubkey tapscript
pub fn create_p2pk_tapscript(pubkey: &[u8]) -> Vec<u8> {
    let mut script = vec![0x20]; // Push 32 bytes
    script.extend_from_slice(pubkey);
    script.push(0xac); // OP_CHECKSIG
    script
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tapleaf_hash() {
        let script = [vec![0x20], vec![0x00; 32]].concat(); // Dummy script
        let leaf = TapLeaf::new(script);
        let hash = leaf.leaf_hash();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_tapbranch_hash() {
        let left = [0x01u8; 32];
        let right = [0x02u8; 32];

        let hash1 = tapbranch_hash(&left, &right);
        let hash2 = tapbranch_hash(&right, &left);

        // Order shouldn't matter (lexicographic sorting)
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_2leaf_taptree() {
        let leaf1 = TapLeaf::new(vec![0x01, 0x02, 0x03]);
        let leaf2 = TapLeaf::new(vec![0x04, 0x05, 0x06]);

        let tree = create_2leaf_taptree(leaf1, leaf2);
        let root = tree.merkle_root();

        assert_eq!(root.len(), 32);
    }

    #[test]
    fn test_3leaf_taptree() {
        let leaf1 = TapLeaf::new(vec![0x01]);
        let leaf2 = TapLeaf::new(vec![0x02]);
        let leaf3 = TapLeaf::new(vec![0x03]);

        let tree = create_3leaf_taptree(leaf1, leaf2, leaf3);
        let root = tree.merkle_root();

        assert_eq!(root.len(), 32);
    }

    #[test]
    fn test_control_block() {
        let internal_pubkey = [0x02u8; 32];
        let merkle_path = vec![[0x03u8; 32], [0x04u8; 32]];

        let control_block =
            compute_control_block(&internal_pubkey, &merkle_path, false, TAPSCRIPT_VER);

        // 1 (version) + 32 (pubkey) + 64 (2 hashes)
        assert_eq!(control_block.len(), 97);
    }
}
