use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;

#[derive(Serialize, Deserialize, Clone)]
pub struct EvidenceEntry {
    pub id: String,
    pub timestamp: String,
    pub collector: String,
    pub source: String,
    pub raw_hash: String,
    pub metadata_hash: String,
    pub combined_hash: String,
    pub payload: Value,
}

pub fn load_from_path(path: &str) -> anyhow::Result<Vec<EvidenceEntry>> {
    let data = fs::read_to_string(path)?;
    let entries: Vec<EvidenceEntry> = serde_json::from_str(&data)?;
    Ok(entries)
}