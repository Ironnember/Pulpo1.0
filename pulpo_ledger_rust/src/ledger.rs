use serde::{Deserialize, Serialize};
use crate::evidence::EvidenceEntry;
use crate::merkle::MerkleNodeExport;

#[derive(Serialize, Deserialize)]
pub struct PulpoLedger {
    pub pulpo_version: String,
    pub exported_at: String,
    pub root_hash: String,
    pub root_signature: Option<String>,
    pub evidence: Vec<EvidenceEntry>,
    pub merkle_tree: MerkleExport,
}

#[derive(Serialize, Deserialize)]
pub struct MerkleExport {
    pub nodes: Vec<MerkleNodeExport>,
}

pub fn export_ledger(
    evidence: Vec<EvidenceEntry>,
    merkle_nodes: Vec<MerkleNodeExport>,
    root_hash: String,
    root_signature: Option<String>,
) -> PulpoLedger {
    PulpoLedger {
        pulpo_version: "1.0".to_string(),
        exported_at: chrono::Utc::now().to_rfc3339(),
        root_hash,
        root_signature,
        evidence,
        merkle_tree: MerkleExport { nodes: merkle_nodes },
    }
}

pub fn write_ledger_json(ledger: &PulpoLedger, path: &str) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(ledger)?;
    std::fs::write(path, json)
}