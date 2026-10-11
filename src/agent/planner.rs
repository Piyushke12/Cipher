//! Advisory planner: ranks candidate investigations, never executes.
//!
//! The LLM decides; the planner only suggests {objective, capability,
//! reason} ordered by priority where prerequisites are satisfied.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    pub objective_id: usize,
    pub family: String,
    pub question: String,
    pub capability: Option<String>,
    pub reason: String,
    pub priority: u8,
}

/// Minimal ranking: unresolved objectives whose resolver (if any) is
/// available, highest priority first. No cost model in v1.
pub fn suggest(
    investigation: &crate::agent::investigation::InvestigationState,
    available_capabilities: &[String],
    limit: usize,
) -> Vec<Candidate> {
    use crate::agent::investigation::ObjectiveStatus;
    let mut out = Vec::new();
    for o in investigation.objectives.iter() {
        if !matches!(
            o.status,
            ObjectiveStatus::Unknown | ObjectiveStatus::NotTested
        ) {
            continue;
        }
        if let Some(cap) = &o.resolving_capability {
            if !available_capabilities.iter().any(|c| c == cap) {
                continue; // prerequisite unavailable: stay quiet, don't checklist
            }
        }
        out.push(Candidate {
            objective_id: o.id,
            family: o.family.clone(),
            question: o.question.clone(),
            capability: o.resolving_capability.clone(),
            reason: format!("unresolved {} question worth testing", o.family),
            priority: o.priority,
        });
    }
    out.sort_by(|a, b| b.priority.cmp(&a.priority));
    out.truncate(limit);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::investigation::InvestigationState;

    #[test]
    fn suggests_only_available_prereqs_in_priority_order() {
        let mut inv = InvestigationState::default();
        inv.ensure("injection", "q1", Some("http.request"), 90);
        inv.ensure("xss", "q2", Some("browser.dom.inspect"), 70);
        inv.ensure("misc", "q3", None, 80);
        let got = suggest(&inv, &["http.request".to_string()], 10);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].family, "injection");
        assert_eq!(got[1].family, "misc");
    }
}
