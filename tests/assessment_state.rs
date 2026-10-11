//! Generic synthetic assessment scenarios (no app-specific logic).
//! Covers: auth transition, newly-reachable reopen, injection lifecycle,
//! authorization, API discovery, scope contamination, dedupe, completion.

use medusa_lib::agent::assessment::AssessmentState;
use medusa_lib::agent::attack_graph::{EdgeKind, NodeKind};
use medusa_lib::agent::completeness::{evaluate, AssessmentStatus, FamilyProgress};
use medusa_lib::agent::families::infer_family;
use medusa_lib::agent::findings::FindingStage;
use medusa_lib::agent::investigation::ObjectiveStatus;
use medusa_lib::model::observation::ObservationDetail;

fn fresh() -> AssessmentState {
    AssessmentState::new("synth", vec!["example.com".into()], 1)
}

// Scenario A: unauthenticated -> user -> admin updates identity + graph.
#[test]
fn scenario_a_auth_state_transition() {
    let mut s = fresh();
    s.target_model.upsert_identity("alice", "user", "authenticated:user");
    s.target_model.current_identity = Some("authenticated:user".into());
    s.attack_graph.upsert_node("id:alice", NodeKind::Identity, "alice", 1);
    s.attack_graph.upsert_node("priv:user", NodeKind::Privilege, "authenticated:user", 1);
    s.attack_graph.link("id:alice", "priv:user", EdgeKind::EscalatesTo);
    s.target_model.upsert_identity("alice", "admin", "authenticated:admin");
    s.target_model.current_identity = Some("authenticated:admin".into());
    s.attack_graph.upsert_node("priv:admin", NodeKind::Privilege, "authenticated:admin", 2);
    s.attack_graph.link("priv:user", "priv:admin", EdgeKind::EscalatesTo);
    assert!(s.attack_graph.path("id:alice", "priv:admin").is_some());
}

// Scenario B: blocked objective reopens when privilege appears.
#[test]
fn scenario_b_newly_reachable_reopens() {
    let mut s = fresh();
    let id = s.investigation.ensure("broken_access_control", "privileged API reachable?", Some("http.request"), 85);
    s.investigation.set_status(id, ObjectiveStatus::Blocked, Some("no admin"));
    let reopened = s.investigation.reopen_blocked("http.request");
    assert_eq!(reopened, vec![id]);
}

// Scenario C: input -> suspicion -> validation -> confirmed (evidence gate).
#[test]
fn scenario_c_injection_lifecycle() {
    let mut s = fresh();
    let fid = s.findings.create("generic input", "t", "injection", "Medium");
    let f = s.findings.get_mut(fid).unwrap();
    assert!(f.transition(FindingStage::Suspected, "").is_err()); // no evidence yet
    f.add_evidence(1);
    assert!(f.transition(FindingStage::Suspected, "s").is_ok());
    assert!(f.transition(FindingStage::EvidenceGathered, "g").is_ok());
    assert!(f.transition(FindingStage::Validated, "v").is_ok());
}

// Scenario D: cross-identity resource access hypothesis stays unconfirmed w/o evidence.
#[test]
fn scenario_d_authorization_needs_evidence() {
    let mut s = fresh();
    let fid = s.findings.create("cross-identity read?", "t", "broken_access_control", "High");
    let f = s.findings.get_mut(fid).unwrap();
    assert_eq!(f.stage, FindingStage::Hypothesis);
    assert!(f.transition(FindingStage::Validated, "").is_err()); // skip + no evidence
}

// Scenario E: API discovery -> params -> graph accepts edges.
#[test]
fn scenario_e_api_discovery_expands_surface() {
    let mut s = fresh();
    s.apply_detail(
        &ObservationDetail::ApiSchema {
            url: "https://example.com/api".into(),
            method: "GET".into(),
            params: vec!["q".into()],
            auth_required: false,
            content_type: None,
        },
        1,
    );
    assert_eq!(s.target_model.params.len(), 1);
    assert!(!s.attack_graph.nodes.is_empty());
}

// Scenario F: unrelated discovered asset is observable but must not execute (policy-level; here: distinct entity).
#[test]
fn scenario_f_scope_contamination_stays_observation() {
    let mut s = fresh();
    s.target_model.upsert_host("example.com", "seed");
    s.target_model.upsert_host("other-domain.net", "tool-output");
    assert_eq!(s.target_model.hosts.len(), 2);
    // No automatic authorization: current_identity unchanged, no privilege granted.
    assert!(s.target_model.current_identity.is_none());
}

// Scenario G: duplicate discovery converges.
#[test]
fn scenario_g_duplicate_convergence() {
    let mut s = fresh();
    s.apply_detail(
        &ObservationDetail::EndpointDiscovered {
            url: "https://example.com/a/".into(),
            status: Some(200),
            title: None,
            tech: vec![],
        },
        1,
    );
    s.apply_detail(
        &ObservationDetail::EndpointDiscovered {
            url: "https://EXAMPLE.com:443/a".into(),
            status: Some(200),
            title: None,
            tech: vec![],
        },
        2,
    );
    assert_eq!(s.target_model.endpoints.len(), 1);
}

// Scenario H/I: completion rejected with remaining, accepted when clear.
#[test]
fn scenario_h_i_completion_gate() {
    let mut inv = medusa_lib::agent::investigation::InvestigationState::default();
    inv.ensure("broken_access_control", "A access B?", Some("http.request"), 90);
    let fams = vec![FamilyProgress {
        family: "broken_access_control".into(),
        status: AssessmentStatus::InProgress,
        tested_questions: 1,
        total_questions: 5,
        evidence_count: 1,
    }];
    let denied = evaluate(&fams, &inv, &["http.request".to_string()], 70);
    assert!(!denied.allowed);
    assert_eq!(denied.remaining.len(), 1);
    for o in inv.objectives.iter().map(|o| o.id).collect::<Vec<_>>() {
        inv.set_status(o, ObjectiveStatus::Resolved, None);
    }
    let allowed = evaluate(&fams, &inv, &["http.request".to_string()], 70);
    assert!(allowed.allowed);
}

// Finding mirror: report → Hypothesis, evidence → promote toward Validated,
// false_positive → Closed. Generic titles only.
#[test]
fn finding_mirror_promotes_with_evidence() {
    let mut s = fresh();
    let fid = s.findings.create("generic sql injection", "t", infer_family("generic sql injection", ""), "High");
    assert_eq!(infer_family("generic sql injection", ""), "injection");
    let f = s.findings.get_mut(fid).unwrap();
    assert!(f.transition(FindingStage::Suspected, "").is_err());
    f.add_evidence(1);
    let reached = s.findings.promote_toward_validated(fid, "confirmed by parser");
    assert_eq!(reached, FindingStage::Validated);
    let f = s.findings.get_mut(fid).unwrap();
    assert!(f.transition(FindingStage::Exploited, "impact").is_ok());
}

// Family inference stays generic (no app fingerprints).
#[test]
fn family_inference_is_generic() {
    assert_eq!(infer_family("Reflected XSS in search", ""), "xss");
    assert_eq!(infer_family("BOLA across accounts", ""), "broken_access_control");
    assert_eq!(infer_family("TLS weak cipher", ""), "cryptographic_issues");
    assert_eq!(infer_family("some novel weakness class", ""), "miscellaneous");
}

// Snapshot round-trips the full state (close/reopen survives).
#[test]
fn snapshot_round_trips_findings_and_graph() {
    use medusa_lib::agent::assessment::{load_in, save_in};
    let dir = std::env::temp_dir().join(format!("medusa-wiring-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut s = AssessmentState::new("snap1", vec!["example.com".into()], 7);
    s.apply_detail(
        &ObservationDetail::PortDiscovered {
            host: "example.com".into(),
            port: 443,
            protocol: "tcp".into(),
            state: "open".into(),
            service: Some("https".into()),
            version: None,
        },
        1,
    );
    let fid = s.findings.create("generic finding", "t", "injection", "High");
    s.findings.get_mut(fid).unwrap().add_evidence(1);
    save_in(&dir, &s).unwrap();
    let back = load_in(&dir, "snap1").unwrap();
    assert_eq!(back.attack_graph.nodes.len(), s.attack_graph.nodes.len());
    assert_eq!(back.findings.findings.len(), 1);
    assert_eq!(back.findings.findings[0].evidence_ids, vec![1]);
    let _ = std::fs::remove_dir_all(&dir);
}

// Assessment id sanitization never yields traversal/dir separators.
#[test]
fn assessment_id_for_target_is_safe() {
    let id = medusa_lib::agent::assessment_id_for_target("https://Example.com:8080/a?x=1", 123);
    assert!(id.starts_with("a-example-com-"));
    assert!(!id.contains('/') && !id.contains('.') && !id.contains(':'));
}

// Summary text derives from state (families, findings, graph, unknowns).
#[test]
fn assessment_summary_text_renders_state() {
    let mut s = fresh();
    s.seed_from_families(&medusa_lib::agent::families::builtin_families(), None);
    s.apply_detail(
        &ObservationDetail::PortDiscovered {
            host: "example.com".into(),
            port: 80,
            protocol: "tcp".into(),
            state: "open".into(),
            service: Some("http".into()),
            version: None,
        },
        1,
    );
    let text = medusa_lib::cli::assess::assessment_summary_text(&s);
    assert!(text.contains("Vulnerability Families"));
    assert!(text.contains("injection"));
    assert!(text.contains("Attack Path"));
    assert!(text.contains("Unknowns"));
}
