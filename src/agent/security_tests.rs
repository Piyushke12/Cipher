//! Security-test registry: what needs establishing, not fixed workflows.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Prerequisite {
    Capability(String),
    HasIdentity,
    HasPrivilege(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestRisk {
    Safe,
    Intrusive,
    Destructive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityTest {
    pub id: String,
    pub family: String,
    pub question: String,
    pub prerequisites: Vec<Prerequisite>,
    pub candidate_capabilities: Vec<String>,
    pub expected_evidence: String,
    pub validation_strategy: String,
    pub risk: TestRisk,
}

pub fn builtin_tests() -> Vec<SecurityTest> {
    vec![
        SecurityTest {
            id: "port_sweep".into(),
            family: "miscellaneous".into(),
            question: "Which network services are exposed?".into(),
            prerequisites: vec![],
            candidate_capabilities: vec!["network.port_scan".into()],
            expected_evidence: "open ports with service hints".into(),
            validation_strategy: "corroborate with service detection".into(),
            risk: TestRisk::Safe,
        },
        SecurityTest {
            id: "http_probe".into(),
            family: "security_misconfiguration".into(),
            question: "Which HTTP endpoints respond?".into(),
            prerequisites: vec![],
            candidate_capabilities: vec!["http.probe".into(), "http.request".into()],
            expected_evidence: "reachable endpoints with status".into(),
            validation_strategy: "repeatable HTTP response".into(),
            risk: TestRisk::Safe,
        },
        SecurityTest {
            id: "auth_boundary_probe".into(),
            family: "broken_access_control".into(),
            question: "Is this resource accessible across identities?".into(),
            prerequisites: vec![Prerequisite::HasIdentity],
            candidate_capabilities: vec!["http.request".into(), "api.bola_testing".into()],
            expected_evidence: "same resource fetched as two identities".into(),
            validation_strategy: "compare responses across identities".into(),
            risk: TestRisk::Safe,
        },
        SecurityTest {
            id: "injection_probe".into(),
            family: "injection".into(),
            question: "Does this input influence backend behavior?".into(),
            prerequisites: vec![],
            candidate_capabilities: vec!["web.injection_testing".into(), "http.request".into()],
            expected_evidence: "differential response to crafted input".into(),
            validation_strategy: "controlled benign payload, no destruction".into(),
            risk: TestRisk::Intrusive,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tests_reference_known_families() {
        let tests = builtin_tests();
        assert!(!tests.is_empty());
        for t in &tests {
            assert!(!t.candidate_capabilities.is_empty());
            assert!(!t.question.is_empty());
        }
    }
}
