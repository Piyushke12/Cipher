//! Finding + hypothesis lifecycle with an evidence gate.
//!
//! A scanner saying "possible X" must never auto-promote to confirmed.
//! Promotion requires linked evidence.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FindingStage {
    Hypothesis,
    Suspected,
    EvidenceGathered,
    Validated,
    Exploited,
    ImpactDemonstrated,
    Chained,
    Closed,
}

impl FindingStage {
    /// Allowed forward transitions (Closed is terminal).
    pub fn can_transition_to(self, next: FindingStage) -> bool {
        use FindingStage::*;
        matches!(
            (self, next),
            (Hypothesis, Suspected)
                | (Hypothesis, Closed)
                | (Suspected, EvidenceGathered)
                | (Suspected, Closed)
                | (EvidenceGathered, Validated)
                | (EvidenceGathered, Closed)
                | (Validated, Exploited)
                | (Validated, Closed)
                | (Exploited, ImpactDemonstrated)
                | (Exploited, Closed)
                | (ImpactDemonstrated, Chained)
                | (ImpactDemonstrated, Closed)
                | (Chained, Closed)
        )
    }

    /// Stages that require at least one evidence reference.
    pub fn requires_evidence(self) -> bool {
        !matches!(self, FindingStage::Hypothesis | FindingStage::Closed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackedFinding {
    pub id: usize,
    pub title: String,
    pub target: String,
    pub family: String,
    pub stage: FindingStage,
    pub severity: String,
    #[serde(default)]
    pub evidence_ids: Vec<usize>,
    #[serde(default)]
    pub note: String,
}

impl TrackedFinding {
    pub fn transition(
        &mut self,
        next: FindingStage,
        note: &str,
    ) -> Result<(), String> {
        if !self.stage.can_transition_to(next) {
            return Err(format!(
                "invalid transition {:?} -> {:?}",
                self.stage, next
            ));
        }
        if next.requires_evidence() && self.evidence_ids.is_empty() {
            return Err("promotion requires linked evidence".to_string());
        }
        self.stage = next;
        self.note = note.to_string();
        Ok(())
    }

    pub fn add_evidence(&mut self, evidence_id: usize) {
        if !self.evidence_ids.contains(&evidence_id) {
            self.evidence_ids.push(evidence_id);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FindingStore {
    pub findings: Vec<TrackedFinding>,
}

impl FindingStore {
    pub fn create(
        &mut self,
        title: &str,
        target: &str,
        family: &str,
        severity: &str,
    ) -> usize {
        let id = self.findings.len() + 1;
        self.findings.push(TrackedFinding {
            id,
            title: title.to_string(),
            target: target.to_string(),
            family: family.to_string(),
            stage: FindingStage::Hypothesis,
            severity: severity.to_string(),
            evidence_ids: Vec::new(),
            note: String::new(),
        });
        id
    }

    pub fn get_mut(&mut self, id: usize) -> Option<&mut TrackedFinding> {
        self.findings.iter_mut().find(|f| f.id == id)
    }

    pub fn get(&self, id: usize) -> Option<&TrackedFinding> {
        self.findings.iter().find(|f| f.id == id)
    }

    /// Promote toward Validated as far as the evidence-gated stepwise
    /// transitions allow (Hypothesis→Suspected→EvidenceGathered→Validated).
    /// Returns the stage reached.
    pub fn promote_toward_validated(&mut self, id: usize, note: &str) -> FindingStage {
        use FindingStage::*;
        let mut reached = match self.get(id) {
            Some(f) => f.stage,
            None => return Hypothesis,
        };
        for next in [Suspected, EvidenceGathered, Validated] {
            let ok = match self.get_mut(id) {
                Some(f) => f.transition(next, note).is_ok(),
                None => false,
            };
            if ok {
                reached = next;
            } else {
                break;
            }
        }
        reached
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_lifecycle_happy_path() {
        let mut s = FindingStore::default();
        let id = s.create("generic injection", "t", "injection", "High");
        let f = s.get_mut(id).unwrap();
        // Hypothesis -> Suspected requires evidence: must fail first.
        assert!(f.transition(FindingStage::Suspected, "").is_err());
        f.add_evidence(1);
        assert!(f.transition(FindingStage::Suspected, "suspicious").is_ok());
        assert!(f.transition(FindingStage::EvidenceGathered, "gathered").is_ok());
        assert!(f.transition(FindingStage::Validated, "validated").is_ok());
        assert!(f.transition(FindingStage::Exploited, "exploited").is_ok());
        assert!(f
            .transition(FindingStage::ImpactDemonstrated, "impact")
            .is_ok());
        assert!(f.transition(FindingStage::Chained, "chained").is_ok());
        assert!(f.transition(FindingStage::Closed, "done").is_ok());
    }

    #[test]
    fn invalid_transitions_rejected() {
        let mut s = FindingStore::default();
        let id = s.create("x", "t", "xss", "Medium");
        let f = s.get_mut(id).unwrap();
        f.add_evidence(9);
        // Skip straight to Validated: rejected.
        assert!(f.transition(FindingStage::Validated, "").is_err());
        // Hypothesis can close directly (false positive).
        assert!(f.transition(FindingStage::Closed, "n/a").is_ok());
    }
}
