//! InvestigationState: persistent unresolved security questions.
//!
//! Distinguishes Unknown / NotTested / TestedNegative / Blocked /
//! NotApplicable — lack of evidence is never a negative result.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ObjectiveStatus {
    Unknown,
    NotTested,
    TestedNegative,
    Blocked,
    NotApplicable,
    Resolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvestigationObjective {
    pub id: usize,
    pub family: String,
    pub question: String,
    pub status: ObjectiveStatus,
    pub resolving_capability: Option<String>,
    #[serde(default)]
    pub blocked_reason: Option<String>,
    pub priority: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InvestigationState {
    pub objectives: Vec<InvestigationObjective>,
}

impl InvestigationState {
    pub fn ensure(
        &mut self,
        family: &str,
        question: &str,
        resolving_capability: Option<&str>,
        priority: u8,
    ) -> usize {
        if let Some(o) = self
            .objectives
            .iter()
            .find(|o| o.family == family && o.question == question)
        {
            return o.id;
        }
        let id = self.objectives.len() + 1;
        self.objectives.push(InvestigationObjective {
            id,
            family: family.to_string(),
            question: question.to_string(),
            status: ObjectiveStatus::Unknown,
            resolving_capability: resolving_capability.map(str::to_string),
            blocked_reason: None,
            priority,
        });
        id
    }

    pub fn set_status(
        &mut self,
        id: usize,
        status: ObjectiveStatus,
        reason: Option<&str>,
    ) -> bool {
        if let Some(o) = self.objectives.iter_mut().find(|o| o.id == id) {
            o.status = status;
            o.blocked_reason = reason.map(str::to_string);
            true
        } else {
            false
        }
    }

    /// Reopen previously blocked objectives when a prerequisite appears
    /// (e.g. credential discovered, privilege obtained).
    pub fn reopen_blocked(&mut self, capability_now_available: &str) -> Vec<usize> {
        let mut reopened = Vec::new();
        for o in self.objectives.iter_mut() {
            if o.status == ObjectiveStatus::Blocked
                && o.resolving_capability.as_deref() == Some(capability_now_available)
            {
                o.status = ObjectiveStatus::Unknown;
                o.blocked_reason = None;
                reopened.push(o.id);
            }
        }
        reopened
    }

    pub fn unresolved_high_value(&self, min_priority: u8) -> Vec<&InvestigationObjective> {
        self.objectives
            .iter()
            .filter(|o| {
                matches!(
                    o.status,
                    ObjectiveStatus::Unknown | ObjectiveStatus::NotTested
                ) && o.priority >= min_priority
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_is_not_negative_and_reopens() {
        let mut s = InvestigationState::default();
        let id = s.ensure("injection", "Does input reach interpreter?", Some("web.injection_testing"), 80);
        assert_eq!(s.objectives[0].status, ObjectiveStatus::Unknown);
        s.set_status(id, ObjectiveStatus::Blocked, Some("no credential"));
        assert_eq!(s.unresolved_high_value(50).len(), 0);
        let reopened = s.reopen_blocked("web.injection_testing");
        assert_eq!(reopened, vec![id]);
        assert_eq!(s.objectives[0].status, ObjectiveStatus::Unknown);
        s.set_status(id, ObjectiveStatus::TestedNegative, None);
        assert!(s.unresolved_high_value(50).is_empty());
    }
}
