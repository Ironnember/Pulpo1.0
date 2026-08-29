use serde::{Deserialize, Serialize};
use crate::evidence::EvidenceEntry;
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize)]
pub struct MerkleNodeExport {
    pub index: usize,
    pub hash: String,
}

pub struct MerkleTree {
    pub nodes: Vec<[u8; 32]>,
    pub root: [u8; 32],
}

impl MerkleTree {
    pub fn from_evidence(evidence: &[EvidenceEntry]) -> Self {
        let mut leaves: Vec<[u8; 32]> = evidence
            .iter()
            .map(|e| {
                let mut hasher = Sha256::new();
                hasher.update(e.combined_hash.as_bytes());
                hasher.finalize().into()
            })
            .collect();

        if leaves.is_empty() {
            let zero = [0u8; 32];
            return Self { nodes: vec![zero], root: zero };
        }

        let mut nodes = leaves.clone();
        while leaves.len() > 1 {
            let mut next = Vec::new();
            for chunk in leaves.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(chunk[0]);
                if chunk.len() == 2 {
                    hasher.update(chunk[1]);
                }
                next.push(hasher.finalize().into());
            }
            nodes.extend(next.clone());
            leaves = next;
        }

        let root = *leaves.first().unwrap();
        Self { nodes, root }
    }

    pub fn root_hash(&self) -> String {
        hex::encode(self.root)
    }

    pub fn export_nodes(&self) -> Vec<MerkleNodeExport> {
        self.nodes
            .iter()
            .enumerate()
            .map(|(i, h)| MerkleNodeExport {
                index: i,
                hash: hex::encode(h),
            })
            .collect()
    }
}