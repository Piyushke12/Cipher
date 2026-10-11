//! AssessmentState: central authoritative security state.
//!
//! The single source of truth for the runtime and context layer.
//! ContextManager projects views from here; it never owns state.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::attack_graph::{AttackGraph, EdgeKind};
use super::completeness::FamilyProgress;
use super::evidence::EvidenceStore;
use super::findings::FindingStore;
use super::investigation::InvestigationState;
use super::target_model::TargetModel;

pub const ASSESSMENT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssessmentState {
    pub schema_version: u32,
    pub id: String,
    /// Every host/URL root currently granted scope — kept in lockstep
    /// with the live session's `ExecutionPolicy` (see
    /// `AgentSession::persist_best_effort`), which is otherwise
    /// in-memory-only and would reset to empty on every reopen.
    #[serde(default)]
    pub target_roots: Vec<String>,
    /// The most recently granted root (`AgentSession::scope_label`) —
    /// distinct from `target_roots` because it is order-dependent (the
    /// *latest* grant wins, not just "a member of the set") and several
    /// runtime decisions key off exactly this value.
    #[serde(default)]
    pub scope_label: String,
    #[serde(default)]
    pub target_model: TargetModel,
    #[serde(default)]
    pub attack_graph: AttackGraph,
    #[serde(default)]
    pub findings: FindingStore,
    #[serde(default)]
    pub evidence: EvidenceStore,
    #[serde(default)]
    pub family_progress: Vec<FamilyProgress>,
    #[serde(default)]
    pub investigation: InvestigationState,
    pub created_at: i64,
    pub updated_at: i64,
    #[serde(default)]
    pub last_completed_step: usize,
}

impl AssessmentState {
    pub fn new(id: &str, target_roots: Vec<String>, now: i64) -> Self {
        Self {
            schema_version: ASSESSMENT_SCHEMA_VERSION,
            id: id.to_string(),
            scope_label: target_roots.first().cloned().unwrap_or_default(),
            target_roots,
            target_model: TargetModel::default(),
            attack_graph: AttackGraph::default(),
            findings: FindingStore::default(),
            evidence: EvidenceStore::default(),
            family_progress: Vec::new(),
            investigation: InvestigationState::default(),
            created_at: now,
            updated_at: now,
            last_completed_step: 0,
        }
    }

    pub fn touch(&mut self, now: i64, step: usize) {
        self.updated_at = now;
        if step > self.last_completed_step {
            self.last_completed_step = step;
        }
    }

    /// Seed investigation objectives from the family registry (idempotent).
    /// Called once per assessment; `focus` boosts one family's priority.
    pub fn seed_from_families(
        &mut self,
        families: &[crate::agent::families::VulnerabilityFamily],
        focus: Option<&str>,
    ) {
        for f in families {
            let boost = match focus {
                Some(focus_id) if focus_id == f.id => 10u8,
                _ => 0u8,
            };
            for q in &f.questions {
                let pri = q.priority.saturating_add(boost).min(100);
                self.investigation.ensure(
                    &f.id,
                    &q.question,
                    q.resolving_capabilities.first().map(|s| s.as_str()),
                    pri,
                );
            }
        }
        // Init family progress rows if absent.
        for f in families {
            if !self.family_progress.iter().any(|p| p.family == f.id) {
                self.family_progress.push(FamilyProgress {
                    family: f.id.clone(),
                    status: crate::agent::completeness::AssessmentStatus::NotStarted,
                    tested_questions: 0,
                    total_questions: f.questions.len(),
                    evidence_count: 0,
                });
            }
        }
    }

    /// Compact LLM-facing projection (never a full graph dump).
    pub fn project_context(&self) -> (Vec<String>, Vec<String>, Vec<String>, Option<String>) {
        let mut attack = Vec::new();
        let privs: Vec<String> = self
            .attack_graph
            .privileges()
            .iter()
            .map(|n| n.label.clone())
            .collect();
        if !privs.is_empty() {
            attack.push(format!("KNOWN PRIVILEGES: {}", privs.join(", ")));
        }
        let fresh: Vec<String> = self
            .attack_graph
            .newly_reachable(self.last_completed_step.saturating_sub(5))
            .iter()
            .map(|n| n.label.clone())
            .collect();
        if !fresh.is_empty() {
            attack.push(format!("NEWLY REACHABLE: {}", fresh.join(", ")));
        }
        if let Some(id) = &self.target_model.current_identity {
            attack.push(format!("CURRENT IDENTITY: {id}"));
        }
        let families: Vec<String> = self
            .family_progress
            .iter()
            .map(|p| {
                format!(
                    "{}: {:?} {}/{} evidence={}",
                    p.family, p.status, p.tested_questions, p.total_questions, p.evidence_count
                )
            })
            .collect();
        let unknowns: Vec<String> = self
            .investigation
            .unresolved_high_value(70)
            .iter()
            .take(10)
            .map(|o| format!("[{}] {} (via {})", o.family, o.question, o.resolving_capability.as_deref().unwrap_or("reasoning")))
            .collect();
        (attack, families, unknowns, None)
    }

    /// Apply a normalized observation detail to the target model + graph.
    /// Generic only: detail variants map to entities/edges, never to
    /// application-specific conclusions. Returns the NEW graph edges
    /// (`from → to [kind]`) created by this observation, for tracing.
    pub fn apply_detail(
        &mut self,
        detail: &crate::model::observation::ObservationDetail,
        step: usize,
    ) -> Vec<(String, String, String)> {
        use crate::model::observation::ObservationDetail as D;
        use crate::agent::attack_graph::{EdgeKind, NodeKind};
        let mut new_edges: Vec<(String, String, String)> = Vec::new();
        // Split borrows so entity merge and graph links coexist.
        let tm = &mut self.target_model;
        let graph = &mut self.attack_graph;
        match detail {
            D::PortDiscovered { host, port, protocol, state, service, version } => {
                let pid = tm.upsert_port(
                    host, *port, protocol, state,
                    service.as_deref(), version.as_deref(),
                );
                let hid = crate::agent::target_model::host_id(host);
                graph.upsert_node(&hid, NodeKind::Asset, host, step);
                graph.upsert_node(&pid, NodeKind::Resource, &format!("{host}:{port}"), step);
                record_link(graph, &hid, &pid, EdgeKind::Exposes, &mut new_edges);
            }
            D::EndpointDiscovered { url, status, tech, .. } => {
                let eid = tm.upsert_endpoint(url, *status, tech);
                graph.upsert_node(&eid, NodeKind::Endpoint, url, step);
            }
            D::VulnerabilityFound { name, url, .. } => {
                let wid = format!("weakness:{name}");
                graph.upsert_node(&wid, NodeKind::Weakness, name, step);
                let eid = crate::agent::target_model::endpoint_id(url);
                graph.upsert_node(&eid, NodeKind::Endpoint, url, step);
                record_link(graph, &eid, &wid, EdgeKind::Contains, &mut new_edges);
            }
            D::SecretFound { rule_id, file, .. } => {
                let cid = format!("credential:{rule_id}:{file}");
                graph.upsert_node(&cid, NodeKind::Credential, rule_id, step);
            }
            D::ApiSchema { url, params, .. } => {
                let eid = tm.upsert_endpoint(url, None, &[]);
                graph.upsert_node(&eid, NodeKind::Endpoint, url, step);
                for p in params {
                    let param_id = tm.upsert_param(url, p, "unknown");
                    graph.upsert_node(&param_id, NodeKind::Input, p, step);
                    record_link(graph, &eid, &param_id, EdgeKind::Accepts, &mut new_edges);
                }
            }
            D::SubdomainDiscovered { host, .. } | D::DnsRecord { host, .. } => {
                let hid = tm.upsert_host(host, "dns");
                graph.upsert_node(&hid, NodeKind::Asset, host, step);
            }
            D::AssetDiscovered { asset, .. } => {
                let hid = tm.upsert_host(asset, "asset");
                graph.upsert_node(&hid, NodeKind::Asset, asset, step);
            }
            _ => {}
        }
        new_edges
    }
}

/// Record a graph edge, collecting it when newly created (for tracing).
fn record_link(
    graph: &mut AttackGraph,
    from: &str,
    to: &str,
    kind: EdgeKind,
    out: &mut Vec<(String, String, String)>,
) {
    if graph.link(from, to, kind) {
        out.push((from.to_string(), to.to_string(), format!("{kind:?}")));
    }
}

pub fn assessments_dir() -> PathBuf {
    crate::infra::cache::state_dir().join("assessments")
}

pub fn is_valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

pub fn save_in(dir: &Path, state: &AssessmentState) -> Result<(), String> {
    if !is_valid_id(&state.id) {
        return Err(format!("invalid assessment id: {}", state.id));
    }
    fs::create_dir_all(dir).map_err(|e| format!("create assessments dir: {e}"))?;
    let text =
        serde_json::to_string_pretty(state).map_err(|e| format!("serialize: {e}"))?;
    fs::write(dir.join(format!("{}.json", state.id)), text)
        .map_err(|e| format!("write assessment: {e}"))?;
    Ok(())
}

pub fn load_in(dir: &Path, id: &str) -> Result<AssessmentState, String> {
    if !is_valid_id(id) {
        return Err(format!("invalid assessment id: {id}"));
    }
    let path = dir.join(format!("{id}.json"));
    let text = fs::read_to_string(&path).map_err(|e| format!("open assessment: {e}"))?;
    let state: AssessmentState =
        serde_json::from_str(&text).map_err(|e| format!("parse assessment: {e}"))?;
    if state.schema_version != ASSESSMENT_SCHEMA_VERSION {
        return Err("stale assessment schema".to_string());
    }
    Ok(state)
}

pub fn save(state: &AssessmentState) -> Result<(), String> {
    save_in(&assessments_dir(), state)
}

pub fn load(id: &str) -> Result<AssessmentState, String> {
    load_in(&assessments_dir(), id)
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("medusa-assess-test-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn survives_close_and_reopen() {
        let dir = temp_dir("reopen");
        let mut s = AssessmentState::new("a1", vec!["example.com".into()], 1);
        s.target_model.upsert_host("example.com", "test");
        s.investigation.ensure("injection", "reaches interpreter?", Some("http.request"), 80);
        save_in(&dir, &s).unwrap();
        drop(s);
        // Simulate app restart: load from disk.
        let back = load_in(&dir, "a1").unwrap();
        assert_eq!(back.target_model.hosts.len(), 1);
        assert_eq!(back.investigation.objectives.len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_traversal_ids() {
        let dir = temp_dir("bad");
        assert!(load_in(&dir, "../evil").is_err());
        let mut s = AssessmentState::new("../evil", vec![], 0);
        s.id = "../evil".into();
        assert!(save_in(&dir, &s).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
