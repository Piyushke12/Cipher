//! EvidenceStore: authoritative raw-evidence log.
//!
//! Principle: write everything, read selectively. The LLM never receives
//! the full store — ContextManager projects a small recent slice.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub id: usize,
    pub capability: String,
    pub provider: String,
    pub tool_id: String,
    pub target: String,
    pub args: String,
    pub output_head: String,
    pub timed_out: bool,
    pub success: bool,
    pub step: usize,
    pub parser_version: u32,
    #[serde(default)]
    pub observation_ids: Vec<usize>,
    #[serde(default)]
    pub finding_ids: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EvidenceStore {
    pub records: Vec<EvidenceRecord>,
}

impl EvidenceStore {
    pub const PARSER_VERSION: u32 = 1;

    pub fn push(
        &mut self,
        capability: &str,
        provider: &str,
        tool_id: &str,
        target: &str,
        args: &str,
        output_head: &str,
        timed_out: bool,
        success: bool,
        step: usize,
    ) -> usize {
        let id = self.records.len() + 1;
        self.records.push(EvidenceRecord {
            id,
            capability: capability.to_string(),
            provider: provider.to_string(),
            tool_id: tool_id.to_string(),
            target: target.to_string(),
            args: args.to_string(),
            output_head: output_head.chars().take(4000).collect(),
            timed_out,
            success,
            step,
            parser_version: Self::PARSER_VERSION,
            observation_ids: Vec::new(),
            finding_ids: Vec::new(),
        });
        id
    }

    pub fn link_observation(&mut self, evidence_id: usize, observation_id: usize) {
        if let Some(r) = self.records.iter_mut().find(|r| r.id == evidence_id) {
            if !r.observation_ids.contains(&observation_id) {
                r.observation_ids.push(observation_id);
            }
        }
    }

    pub fn link_finding(&mut self, evidence_id: usize, finding_id: usize) {
        if let Some(r) = self.records.iter_mut().find(|r| r.id == evidence_id) {
            if !r.finding_ids.contains(&finding_id) {
                r.finding_ids.push(finding_id);
            }
        }
    }

    pub fn recent(&self, n: usize) -> Vec<&EvidenceRecord> {
        let len = self.records.len();
        let start = len.saturating_sub(n);
        self.records[start..].iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_links_and_recent_slice() {
        let mut s = EvidenceStore::default();
        let a = s.push("http.probe", "httpx", "httpx", "t", "", "ok", false, true, 1);
        let b = s.push("network.port_scan", "nmap", "nmap", "t", "", "ok", false, true, 2);
        s.link_observation(a, 7);
        s.link_observation(a, 7);
        assert_eq!(s.records[0].observation_ids, vec![7]);
        assert_eq!(s.recent(1).len(), 1);
        assert_eq!(s.recent(1)[0].id, b);
    }
}
