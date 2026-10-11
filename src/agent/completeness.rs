//! Completeness engine: the LLL proposes finish, Cipher disposes.
//!
//! Completion is a state problem, never a coverage percentage or a count
//! of tools executed.

use serde::{Deserialize, Serialize};

use super::investigation::{InvestigationState, ObjectiveStatus};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AssessmentStatus {
    NotStarted,
    InProgress,
    Tested,
    ConfirmedFinding,
    Blocked,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FamilyProgress {
    pub family: String,
    pub status: AssessmentStatus,
    pub tested_questions: usize,
    pub total_questions: usize,
    pub evidence_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemainingObjective {
    pub family: String,
    pub question: String,
    pub priority: u8,
    pub resolving_capability: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletionDecision {
    pub allowed: bool,
    pub reason: String,
    pub remaining: Vec<RemainingObjective>,
}

/// Evaluate whether a proposed finish is allowed.
///
/// Rules:
/// - No evidence and no tested questions -> deny.
/// - Any high-value unresolved objective with an available resolver -> deny.
/// - Blocked / NotApplicable / TestedNegative never block by themselves.
/// - Otherwise allow.
pub fn evaluate(
    families: &[FamilyProgress],
    investigation: &InvestigationState,
    available_capabilities: &[String],
    min_high_value_priority: u8,
) -> CompletionDecision {
    let mut remaining = Vec::new();
    for o in investigation.objectives.iter() {
        let unresolved = matches!(
            o.status,
            ObjectiveStatus::Unknown | ObjectiveStatus::NotTested
        );
        if !unresolved || o.priority < min_high_value_priority {
            continue;
        }
        let resolver_available = match &o.resolving_capability {
            None => true, // reasoning question, still counts
            Some(cap) => available_capabilities.iter().any(|c| c == cap),
        };
        if resolver_available {
            remaining.push(RemainingObjective {
                family: o.family.clone(),
                question: o.question.clone(),
                priority: o.priority,
                resolving_capability: o.resolving_capability.clone(),
            });
        }
    }
    remaining.sort_by(|a, b| b.priority.cmp(&a.priority));

    let any_progress = families.iter().any(|f| {
        matches!(
            f.status,
            AssessmentStatus::Tested
                | AssessmentStatus::ConfirmedFinding
                | AssessmentStatus::InProgress
        ) || f.evidence_count > 0
    });

    if !any_progress && remaining.is_empty() {
        // Check if there is literally nothing to do (all NA/blocked).
        let all_settled = families.iter().all(|f| {
            matches!(
                f.status,
                AssessmentStatus::Blocked | AssessmentStatus::NotApplicable
            )
        });
        if all_settled && !families.is_empty() {
            return CompletionDecision {
                allowed: true,
                reason: "all families blocked or not applicable".into(),
                remaining: vec![],
            };
        }
        return CompletionDecision {
            allowed: false,
            reason: "empty assessment cannot finish".into(),
            remaining,
        };
    }

    if !remaining.is_empty() {
        return CompletionDecision {
            allowed: false,
            reason: "high-value unresolved security questions remain".into(),
            remaining,
        };
    }

    CompletionDecision {
        allowed: true,
        reason: "no meaningful unresolved objectives".into(),
        remaining: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::investigation::InvestigationState;

    fn fams(status: AssessmentStatus) -> Vec<FamilyProgress> {
        vec![FamilyProgress {
            family: "injection".into(),
            status,
            tested_questions: 1,
            total_questions: 4,
            evidence_count: 1,
        }]
    }

    #[test]
    fn empty_assessment_cannot_finish() {
        let inv = InvestigationState::default();
        let d = evaluate(&[], &inv, &[], 70);
        assert!(!d.allowed);
    }

    #[test]
    fn one_finding_does_not_auto_permit_finish() {
        let mut inv = InvestigationState::default();
        inv.ensure("broken_access_control", "Can A access B's resource?", Some("api.bola_testing"), 90);
        let d = evaluate(
            &fams(AssessmentStatus::ConfirmedFinding),
            &inv,
            &["api.bola_testing".to_string()],
            70,
        );
        assert!(!d.allowed);
        assert_eq!(d.remaining.len(), 1);
    }

    #[test]
    fn blocked_and_na_families_can_complete() {
        let inv = InvestigationState::default();
        let d = evaluate(
            &[FamilyProgress {
                family: "xxe".into(),
                status: AssessmentStatus::Blocked,
                tested_questions: 0,
                total_questions: 1,
                evidence_count: 0,
            }],
            &inv,
            &[],
            70,
        );
        assert!(d.allowed);
    }

    #[test]
    fn all_objectives_complete_permits_finish() {
        let mut inv = InvestigationState::default();
        let id = inv.ensure("xss", "Reflected?", Some("http.request"), 60);
        inv.set_status(id, crate::agent::investigation::ObjectiveStatus::Resolved, None);
        let d = evaluate(&fams(AssessmentStatus::Tested), &inv, &["http.request".to_string()], 70);
        assert!(d.allowed);
    }

    #[test]
    fn unavailable_resolver_does_not_block() {
        let mut inv = InvestigationState::default();
        inv.ensure("xss", "Stored?", Some("browser.dom.inspect"), 90);
        let d = evaluate(&fams(AssessmentStatus::Tested), &inv, &["http.request".to_string()], 70);
        assert!(d.allowed);
    }
}
