//! The generic investigation loop. Target in, findings out —
//! the loop body never branches on assessment type.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use crate::model::EnvironmentState;
use crate::registry::{CapabilityRegistry, ToolRegistry};

use super::assessment::AssessmentState;
use super::context::{ContextManager, Finding};
use super::events::AgentEvent;
use super::executor::{LocalProcessExecutor, ProcessExecutor, ToolResult};
use super::model::{ContextView, Decision, ModelError, ModelProvider};
use super::policy::{ExecutionPolicy, PolicyError};
use super::provider::{CapabilityRequest, ExecutionContext, ProviderRegistry};
use super::vault::VaultManager;

/// What is being assessed. Deliberately thin in Phase 1; the world model
/// (Phase 3) builds the asset graph from this seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// e.g. "10.0.0.10", "https://example.internal", "/path/to/repo".
    pub address: String,
    /// Optional scope note, e.g. profile id ("high_coverage").
    pub profile: Option<String>,
}

impl Target {
    pub fn new(address: &str) -> Self {
        Self {
            address: address.to_string(),
            profile: None,
        }
    }
}

/// A validated-but-not-yet-executed action. Phase 4 turns these into real
/// `ToolCall`s; until then they prove the loop resolves capabilities to
/// providers correctly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedAction {
    pub step: usize,
    pub capability: String,
    pub provider: String,
    pub target: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinishReason {
    ModelFinished(String),
    MaxSteps(usize),
    Cancelled,
    TooManyModelErrors { count: usize, last_error: String },
    ConfigError(String),
    ContextExhausted,
}

#[derive(Debug, Clone)]
pub struct InvestigationResult {
    pub target: Target,
    pub steps_taken: usize,
    pub planned_actions: Vec<PlannedAction>,
    pub tool_results: Vec<ToolResult>,
    pub finish_reason: FinishReason,
    /// If the investigation ended due to model errors, the last error message.
    pub model_error: Option<String>,
}

/// External cancellation handle. Clone it into another thread / Ctrl-C
/// handler and call `cancel()`; the loop observes it every iteration.
#[derive(Debug, Clone, Default)]
pub struct RuntimeHandle {
    cancelled: Arc<AtomicBool>,
}

impl RuntimeHandle {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Clear a previous cancellation. Called at every turn boundary so
    /// Stop applies to the turn in flight only: without this, one Stop
    /// latches the flag and every later turn insta-cancels at the top
    /// of the drive loop — the session looks alive but never acts again.
    pub fn reset(&self) {
        self.cancelled.store(false, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// The shared cancel flag, for components that must react to a Stop
    /// without a reference to the whole handle — notably the process
    /// executor, which kills the in-flight child when this flips.
    pub fn flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancelled)
    }
}

pub struct AgentRuntime<'a> {
    model: std::cell::RefCell<Box<dyn ModelProvider>>,
    policy: ExecutionPolicy,
    /// Optional decision budget. `None` (default) = unlimited: turns end
    /// when the model replies/finishes, the user cancels, or a circuit
    /// breaker (consecutive model errors, tool failures) trips.
    max_steps: Option<usize>,
    max_consecutive_errors: usize,
    /// Model context window in tokens (default 128k). The drive loop
    /// tracks per-decision usage against this for the context meter and
    /// auto-compaction. Provider `usage` blocks are authoritative; a
    /// char/4 estimate fills in when the endpoint omits them.
    context_tokens: u64,
    /// Auto-compact when usage reaches this percent of `context_tokens`
    /// (default 85). At least `MIN_STEPS_BETWEEN_COMPACTIONS` decisions
    /// of progress are required between compactions — re-crossing the
    /// threshold sooner means even a fresh summary cannot fit, and the
    /// turn ends with `ContextExhausted` instead of thrashing.
    compaction_threshold_pct: u8,
    /// Conversation turns kept verbatim across a compaction (default 4).
    compact_keep_turns: usize,
    handle: RuntimeHandle,
    caps: &'a CapabilityRegistry,
    state: &'a EnvironmentState,
    /// Capability → provider resolution (the allow-list). Built from the
    /// tool registry; the LLM never selects providers.
    providers: ProviderRegistry,
    /// Injectable executor (tests, dry runs). Production defaults to the
    /// local process executor: direct spawn, no shell, with timeout.
    executor: Option<Arc<dyn ProcessExecutor>>,
    /// Blocking approval gate for interactive UIs (see
    /// [`AgentRuntime::with_approval_gate`]). `None` in headless/CLI runs.
    approval_gate: Option<std::sync::Arc<std::sync::Mutex<Option<bool>>>>,
    /// Debug-trace sink (see `infra::trace`). `None` = tracing off (tests,
    /// headless runs without a session file). When set, every LLM call,
    /// decision, tool invocation and state mutation is appended as JSONL.
    tracer: std::cell::RefCell<Option<Box<dyn FnMut(crate::infra::trace::TraceEntry) + Send>>>,
    /// Drained at each step boundary in `drive()`: returns user messages
    /// that arrived mid-turn. They are folded into the SAME turn — appended
    /// to the conversation and run through scope-granting — so the next
    /// model call sees them and adapts, instead of the turn stopping and a
    /// fresh turn starting. `None` in CLI/headless runs: no live mailbox.
    input_drain: Option<Arc<dyn Fn() -> Vec<String> + Send + Sync>>,
    /// Consulted at each step boundary in `drive()`: returns a replacement
    /// model provider when the operator switched providers mid-turn, else
    /// `None`. The swap is applied BEFORE the next LLM request, so a
    /// provider change takes effect on the very next step (like Claude
    /// Code / Codex) instead of waiting for the whole turn to end. `None`
    /// in CLI/headless runs: no live provider switch.
    model_reload: Option<Arc<dyn Fn() -> Option<Box<dyn ModelProvider>> + Send + Sync>>,
}

impl<'a> AgentRuntime<'a> {
    pub fn new(
        model: Box<dyn ModelProvider>,
        tools: &'a ToolRegistry,
        caps: &'a CapabilityRegistry,
        state: &'a EnvironmentState,
    ) -> Self {
        let mut providers = ProviderRegistry::from_tools(tools);
        // Internal providers ship with medusa itself (no external tool):
        // the raw HTTP request provider behind http.request /
        // api.auth_testing / api.bola_testing, and the web-research
        // provider behind web.research (fetch + extract).
        providers.register(std::sync::Arc::new(
            super::http_provider::HttpRequestProvider::new(),
        ));
        providers.register(std::sync::Arc::new(super::research::ResearchProvider::new()));
        Self {
            model: std::cell::RefCell::new(model),
            policy: ExecutionPolicy::default(),
            max_steps: None,
            max_consecutive_errors: 5,
            context_tokens: 128_000,
            compaction_threshold_pct: 85,
            compact_keep_turns: 4,
            handle: RuntimeHandle::default(),
            caps,
            state,
            providers,
            executor: None,
            approval_gate: None,
            tracer: std::cell::RefCell::new(None),
            input_drain: None,
            model_reload: None,
        }
    }

    /// Attach a debug-trace sink (per-session JSONL writer). The sink is
    /// `Send` so runtimes keep working on worker threads; calls are
    /// synchronous appends and never fail the loop.
    pub fn with_tracer<F>(self, f: F) -> Self
    where
        F: FnMut(crate::infra::trace::TraceEntry) + Send + 'static,
    {
        *self.tracer.borrow_mut() = Some(Box::new(f));
        self
    }

    /// Swap the model provider at runtime (e.g. the desktop's provider
    /// switch). Interior mutability: the session borrows the runtime
    /// immutably, so a plain `&mut self` setter would not compile — and
    /// would race a running turn anyway. Between turns this is safe: the
    /// worker mailbox is drained sequentially on one thread.
    pub fn swap_model(&self, model: Box<dyn ModelProvider>) {
        let mut model = model;
        // The replacement must share the cancel flag too, or a Stop after
        // a provider switch could no longer interrupt the model call.
        model.set_cancel_flag(self.handle.flag());
        *self.model.borrow_mut() = model;
    }

    /// Display name of the active model (for UI labels).
    pub fn model_name(&self) -> String {
        self.model.borrow().name().to_string()
    }

    /// Cap model-decisions per turn (per run when autonomous). Unbounded by
    /// default; set only when a hard budget is explicitly wanted.
    pub fn with_max_steps(mut self, n: usize) -> Self {
        self.max_steps = Some(n);
        self
    }

    /// Model context window in tokens for the context meter and
    /// auto-compaction threshold.
    pub fn with_context_window(mut self, tokens: u64) -> Self {
        if tokens > 0 {
            self.context_tokens = tokens;
        }
        self
    }

    /// Auto-compact threshold as a 0-100 percent of the context window.
    pub fn with_compaction_threshold(mut self, pct: u8) -> Self {
        if pct > 0 && pct <= 100 {
            self.compaction_threshold_pct = pct;
        }
        self
    }

    /// Conversation turns kept verbatim across a compaction.
    pub fn with_compact_keep_turns(mut self, n: usize) -> Self {
        self.compact_keep_turns = n;
        self
    }

    /// Source of mid-turn user messages, drained at each step boundary.
    /// Returned messages are folded into the running turn (conversation +
    /// scope) so the agent adapts on its next model call without stopping.
    pub fn with_input_drain<F>(mut self, f: F) -> Self
    where
        F: Fn() -> Vec<String> + Send + Sync + 'static,
    {
        self.input_drain = Some(Arc::new(f));
        self
    }

    /// Source of a mid-turn provider switch. `f` returns `Some(model)` once
    /// after the operator picks a new provider (and `None` otherwise); the
    /// drive loop applies it before the next LLM request so the switch takes
    /// effect on the very next step rather than after the turn ends.
    pub fn with_model_reload<F>(mut self, f: F) -> Self
    where
        F: Fn() -> Option<Box<dyn ModelProvider>> + Send + Sync + 'static,
    {
        self.model_reload = Some(Arc::new(f));
        self
    }

    /// Inject a process executor (tests, dry runs). Production defaults to
    /// the local process executor — direct `Command::new(exe).args(argv)`,
    /// never a shell.
    pub fn with_executor(mut self, executor: Arc<dyn ProcessExecutor>) -> Self {
        self.executor = Some(executor);
        self
    }

    /// Inject an externally-created handle so callers can cancel before
    /// the runtime is even moved into its worker thread.
    pub fn with_handle(mut self, handle: RuntimeHandle) -> Self {
        // Hand the model the same cancel flag so a Stop interrupts an
        // in-flight CLI-harness model call, not just tool executions.
        self.model.borrow_mut().set_cancel_flag(handle.flag());
        self.handle = handle;
        self
    }

    /// Share the TUI approval flag so high-risk Destructive tests can be
    /// approved mid-investigation without restarting the runtime.
    pub fn with_approval_flag(
        mut self,
        flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        self.policy.allow_destructive = flag;
        self
    }

    /// Blocking approval gate for interactive UIs: when a high-risk
    /// capability is rejected, the drive loop WAITS here for the user's
    /// decision instead of racing ahead (the model would retry before the
    /// dialog is even clicked). `Some(true)` approves (and latches the
    /// flag), `Some(false)` denies and feeds the rejection back. `None`
    /// means undecided; without a gate (CLI), behavior is unchanged.
    pub fn with_approval_gate(
        mut self,
        gate: std::sync::Arc<std::sync::Mutex<Option<bool>>>,
    ) -> Self {
        self.approval_gate = Some(gate);
        self
    }

    pub fn handle(&self) -> RuntimeHandle {
        self.handle.clone()
    }

    /// Headless entry point: same loop, events discarded. Tests and
    /// `--json` flows use this; live UI uses [`Self::investigate_with`].
    pub fn investigate(&self, target: Target) -> InvestigationResult {
        self.investigate_with(target, &mut |_| {})
    }

    /// Investigation loop with an event listener. The listener is passive:
    /// it observes but never influences the loop, so replaying recorded
    /// events reproduces the run deterministically. `FnMut` (not `Fn`) so
    /// live renderers can hold UI state; tests use a `RefCell<Vec>`.
    pub fn investigate_with(
        &self,
        target: Target,
        emit: &mut dyn FnMut(AgentEvent),
    ) -> InvestigationResult {
        self.investigate_with_state(target, emit).0
    }

    /// Same as [`Self::investigate_with`] but also returns the authoritative
    /// [`AssessmentState`] snapshot so UIs can render families, findings,
    /// attack paths, identity/privilege, unknowns, and completion from
    /// runtime state instead of hardcoded data.
    pub fn investigate_with_state(
        &self,
        target: Target,
        emit: &mut dyn FnMut(AgentEvent),
    ) -> (InvestigationResult, AssessmentState) {
        use super::events::AgentEvent as Ev;

        emit(Ev::InvestigationStarted {
            target: target.address.clone(),
        });
        // Autonomous (CLI) semantics: the declared target IS the scope.
        let mut sess = self.session();
        sess.policy = self.policy.for_target(&target.address);
        sess.scope_label = target.address.clone();
        sess.assessment.id = assessment_id_for_target(
            &target.address,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0),
        );
        sess.assessment.target_roots = vec![target.address.clone()];
        // Autonomous mode for the brief; no staged note carries across
        // investigations sharing a process.
        sess.cm.set_autonomous(true);
        sess.cm.clear_staged_model_note();
        sess.trace(
            crate::infra::trace::tag::ASSESSMENT_START,
            format!("assessment {} on {}", sess.assessment.id, target.address),
            serde_json::json!({
                "assessment": sess.assessment.id,
                "target": target.address,
            }),
        );
        sess.persist_best_effort();
        let outcome = sess.drive(true, emit);
        let finish_reason = match outcome {
            DriveOutcome::Finished(r) => FinishReason::ModelFinished(r),
            DriveOutcome::MaxSteps(n) => FinishReason::MaxSteps(n),
            DriveOutcome::Cancelled => FinishReason::Cancelled,
            DriveOutcome::TooManyModelErrors { count, last_error } => {
                FinishReason::TooManyModelErrors { count, last_error }
            }
            DriveOutcome::ConfigError(e) => FinishReason::ConfigError(e),
            DriveOutcome::ContextExhausted => FinishReason::ContextExhausted,
            // Unreachable: autonomous drive treats reply as narration and
            // continues. Mapped defensively regardless.
            DriveOutcome::Replied(r) => FinishReason::ModelFinished(r),
        };
        let reason_text = match &finish_reason {
            FinishReason::ModelFinished(r) => r.clone(),
            FinishReason::MaxSteps(n) => format!("max steps ({n}) reached"),
            FinishReason::Cancelled => "cancelled".to_string(),
            FinishReason::TooManyModelErrors { count, last_error } => {
                format!("model failed {count} times in a row: {last_error}")
            }
            FinishReason::ConfigError(e) => format!("misconfigured: {e}"),
            FinishReason::ContextExhausted => {
                "context window exhausted even after compaction — findings and vault preserved; start a new run to continue".to_string()
            }
        };
        sess.trace(
            crate::infra::trace::tag::ASSESSMENT_FINISH,
            format!("assessment {} finished: {}", sess.assessment.id, reason_text.chars().take(120).collect::<String>()),
            serde_json::json!({
                "assessment": sess.assessment.id,
                "steps_taken": sess.step,
                "tool_results": sess.tool_results.len(),
            }),
        );
        emit(Ev::Finished {
            reason: reason_text,
        });
        let assessment = sess.assessment.clone();
        (sess.into_result(target, finish_reason), assessment)
    }

    /// A fresh interactive session: persistent context and scope across
    /// turns. Scope starts EMPTY — nothing may execute until the user
    /// mentions a target (parsed by us, never the model).
    ///
    /// Every call shares the literal assessment id `"session"` — fine for
    /// a single chat, but a caller that keeps several interactive
    /// sessions alive (e.g. one per desktop chat tab) must use
    /// [`Self::session_with_id`] instead, or every chat's
    /// `persist_best_effort` snapshot overwrites the same file.
    pub fn session(&self) -> AgentSession<'_, 'a> {
        self.session_with_id("session")
    }

    /// [`Self::session`] with an explicit, caller-chosen assessment id
    /// (validated the same way [`super::assessment::save_in`] validates
    /// one at persist time — an invalid id just means persistence will
    /// fail safely later, never a panic here). Use this whenever more
    /// than one interactive session may be live at once, so each gets
    /// its own snapshot file instead of silently sharing `"session"`.
    pub fn session_with_id(&self, id: &str) -> AgentSession<'_, 'a> {
        let now = super::assessment::now_unix();
        let mut assessment = AssessmentState::new(id, Vec::new(), now);
        assessment.seed_from_families(&super::families::builtin_families(), None);
        AgentSession {
            rt: self,
            env: self.state.clone(),
            cm: ContextManager::new(),
            assessment,
            tool_results: Vec::new(),
            consecutive_errors: 0,
            consecutive_slow_errors: 0,
            step: 0,
            finish_denies: 0,
            repeat_fail_sig: String::new(),
            repeat_fail_count: 0,
            repeat_fail_state: 0,
            repeat_fail_last: String::new(),
            breaker_trips: 0,
            hypothesis_seq: 0,
            policy: self.policy.for_session(),
            scope_label: String::new(),
            approval_denied: false,
            model_secs_step: 0.0,
            used_tokens: 0,
            // Start "long ago" so the first threshold crossing compacts
            // immediately instead of looking like thrash.
            steps_since_compact: 1_000_000,
            vault: None,
        }
    }

    fn context_view(
        &self,
        env: &EnvironmentState,
        target: &Target,
        step: usize,
        cm: &ContextManager,
    ) -> ContextView {
        // Advertise only what provider selection would actually accept:
        // env health says a tool is installed, but the argv guard (no
        // `{target}` slot — zap GUI, rizin REPL, …) can still make every
        // provider of a capability unusable. Advertising those lures the
        // model into guaranteed rejections.
        let mut available: Vec<String> = env
            .available_capabilities()
            .into_iter()
            .filter(|cap| {
                self.providers
                    .all()
                    .iter()
                    .any(|p| p.capabilities().iter().any(|c| c == cap) && p.is_available(env))
            })
            .map(|s| s.to_string())
            .collect();
        available.sort();
        // Semantic option schemas for available capabilities, so the model
        // knows which options it may pass (and only those).
        let capability_schemas: Vec<String> = self
            .caps
            .all()
            .iter()
            .filter(|c| available.contains(&c.id))
            .map(|c| {
                if c.options.is_empty() {
                    format!("{}: no options", c.id)
                } else {
                    format!(
                        "{}: {}",
                        c.id,
                        c.options
                            .iter()
                            .map(|o| o.hint())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                }
            })
            .collect();
        let (view, report) = cm.build_view_with_schemas(
            target,
            step,
            available,
            env.unavailable_capabilities().len(),
            capability_schemas,
        );
        if let Some(tracer) = self.tracer.borrow_mut().as_mut() {
            tracer(crate::infra::trace::TraceEntry::new(
                step,
                "",
                crate::infra::trace::tag::CONTEXT_BUILT,
                format!(
                    "context built: {} chars (elided obs {}/{}, evidence {}, narr {}, actions {})",
                    report.total_chars,
                    report.elided_observations,
                    view.observations.len(),
                    report.elided_evidence,
                    report.elided_narrations,
                    report.elided_actions,
                ),
                serde_json::json!({
                    "total_chars": report.total_chars,
                    "elided_observations": report.elided_observations,
                    "elided_evidence": report.elided_evidence,
                    "elided_narrations": report.elided_narrations,
                    "elided_actions": report.elided_actions,
                    "observations_kept": view.observations.len(),
                    "findings_kept": view.findings.len(),
                }),
            ));
        }
        view
    }

    /// Resume a previously persisted assessment into a live session.
    /// Replays tracked findings into the ContextManager registry so the
    /// model sees them immediately; observations/graph/evidence ride the
    /// projection from the loaded state.
    pub fn resume_session(&self, assessment: AssessmentState) -> AgentSession<'_, 'a> {
        let mut sess = self.session();
        for f in assessment.findings.findings.clone() {
            sess.cm.replay_finding(Finding {
                id: f.id,
                severity: f.severity.clone(),
                title: f.title.clone(),
                target: f.target.clone(),
                source: "replay".into(),
                detail: f.note.clone(),
                status: match f.stage {
                    super::findings::FindingStage::Validated
                    | super::findings::FindingStage::Exploited
                    | super::findings::FindingStage::ImpactDemonstrated
                    | super::findings::FindingStage::Chained => "confirmed".into(),
                    super::findings::FindingStage::Closed => "false_positive".into(),
                    _ => "open".into(),
                },
                step_found: 0,
                step_updated: 0,
            });
        }
        sess.step = assessment.last_completed_step;
        restore_scope(&mut sess, &assessment.target_roots, &assessment.scope_label);
        sess.assessment = assessment;
        sess
    }

    /// [`Self::resume_session`] plus a previously persisted
    /// [`ContextManager`] snapshot (see `context::save`/`context::load`).
    /// This is the full resume path: `assessment` restores the
    /// authoritative world model (attack graph, target model, family
    /// progress, evidence log) AND the granted scope (otherwise
    /// in-memory-only — see `persist_best_effort`), and `cm` restores
    /// everything the session log's record-by-record replay could not
    /// reconstruct — prior actions (with their reason and
    /// effectiveness), raw tool evidence, and the error history —
    /// instead of leaving them wiped on every reopen. `cm`'s own
    /// findings/narrations/conversation supersede the ones
    /// `resume_session` would have replayed from `assessment` alone, so
    /// this skips that replay rather than doing it twice.
    pub fn resume_session_with_context(
        &self,
        assessment: AssessmentState,
        cm: ContextManager,
    ) -> AgentSession<'_, 'a> {
        let mut sess = self.session_with_id(&assessment.id);
        sess.step = assessment.last_completed_step;
        restore_scope(&mut sess, &assessment.target_roots, &assessment.scope_label);
        sess.assessment = assessment;
        sess.cm = cm;
        sess
    }
}

/// Re-grant every persisted scope root and restore the primary label.
/// `ExecutionPolicy` is never itself serialized — this is the only way a
/// resumed session regains the ability to act on anything, instead of
/// every action rejecting with "outside assessment scope ('')" the way
/// a brand new, never-granted session would.
fn restore_scope(sess: &mut AgentSession<'_, '_>, target_roots: &[String], scope_label: &str) {
    for root in target_roots {
        sess.policy.grant_scope(root);
    }
    sess.scope_label = if !scope_label.is_empty() {
        scope_label.to_string()
    } else {
        target_roots.first().cloned().unwrap_or_default()
    };
}

/// Short decision classifier for traces (no payload).
fn decision_kind(d: &super::model::Decision) -> &'static str {
    use super::model::Decision::*;
    match d {
        Execute { .. } => "execute",
        CreateHypothesis { .. } => "hypothesis",
        Finish { .. } => "finish",
        Reply { .. } => "reply",
        Narrate { .. } => "narrate",
        WebSearch { .. } => "web_search",
        FileRead { .. } => "file_read",
        FileWrite { .. } => "file_write",
        ReportFinding { .. } => "report_finding",
        UpdateFinding { .. } => "update_finding",
        VaultStore { .. } => "vault_store",
        VaultRecall { .. } => "vault_recall",
    }
}

/// Redacted decision detail for traces: identifiers and lengths only.
/// Free text (reason/statement/text/query) is length + scrubbed head:
/// the model may echo tokens it just read.
fn decision_trace_detail(d: &super::model::Decision) -> serde_json::Value {
    use super::model::Decision::*;
    let head = |s: &str| {
        crate::infra::trace::scrub_text(&s.chars().take(300).collect::<String>(), 300)
    };
    match d {
        Execute {
            capability,
            target,
            options,
            reason,
        } => serde_json::json!({
            "capability": capability,
            "target": target,
            "options": sanitized_options(options),
            "reason_len": reason.chars().count(),
        }),
        CreateHypothesis {
            statement,
            confidence,
        } => serde_json::json!({"statement_head": head(statement), "confidence": confidence}),
        Finish { reason } => serde_json::json!({"reason_len": reason.chars().count()}),
        Reply { text } | Narrate { text } => {
            serde_json::json!({"text_len": text.chars().count(), "text_head": head(text)})
        }
        WebSearch { query, .. } => serde_json::json!({"query_len": query.chars().count()}),
        FileRead { path, grep, lines, .. } => serde_json::json!({
            "path": path, "grep": grep, "lines": lines,
        }),
        FileWrite { path, content, .. } => serde_json::json!({
            "path": path, "content_len": content.chars().count(),
        }),
        ReportFinding {
            severity,
            title,
            target,
            detail,
        } => serde_json::json!({
            "severity": severity, "title": title, "target": target,
            "detail_len": detail.chars().count(),
        }),
        UpdateFinding { id, status, .. } => serde_json::json!({"id": id, "status": status}),
        VaultStore { key, kind, source, .. } => serde_json::json!({
            "key": key, "kind": kind, "source": source,
        }),
        VaultRecall { query } => serde_json::json!({"query": query}),
    }
}

/// Short drive-outcome classifier for traces.
fn drive_outcome_kind(o: &DriveOutcome) -> &'static str {
    match o {
        DriveOutcome::Replied(_) => "replied",
        DriveOutcome::Finished(_) => "finished",
        DriveOutcome::MaxSteps(_) => "max_steps",
        DriveOutcome::Cancelled => "cancelled",
        DriveOutcome::TooManyModelErrors { .. } => "too_many_model_errors",
        DriveOutcome::ConfigError(_) => "config_error",
        DriveOutcome::ContextExhausted => "context_exhausted",
    }
}

/// Redacted option summary for traces: option NAMES plus value kind and
/// length — never values (they may carry tokens, passwords, bodies).
fn sanitized_options(options: &super::model::OptionSet) -> serde_json::Value {    let map: serde_json::Map<String, serde_json::Value> = options
        .iter()
        .map(|(k, v)| {
            let desc = match v {
                super::model::OptionValue::Str(s) => {
                    format!("str(len={})", s.chars().count())
                }
                super::model::OptionValue::Num(n) => format!("num({n})"),
                super::model::OptionValue::Bool(b) => format!("bool({b})"),
                // Header/option NAMES only — values may be tokens.
                super::model::OptionValue::Map(m) => {
                    format!("map{{{}}}", m.keys().cloned().collect::<Vec<_>>().join(","))
                }
            };
            (k.clone(), serde_json::Value::String(desc))
        })
        .collect();
    serde_json::Value::Object(map)
}

/// Filesystem-safe assessment id for a target (`a-<host>-<millis>`).
pub fn assessment_id_for_target(target: &str, now_ms: i64) -> String {    let host = super::policy::host_of(target);
    let mut clean: String = host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    clean = clean.trim_matches('-').to_string();
    if clean.is_empty() {
        clean = "target".to_string();
    }
    if clean.len() > 40 {
        clean.truncate(40);
    }
    format!("a-{clean}-{now_ms}")
}

/// Outcome of a blocking approval wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApprovalDecision {
    Allow,
    Deny,
    /// No gate wired (headless) or the user never answered.
    None,
}

/// System prompt for the compaction summarizer. The summary REPLACES
/// older conversation turns: it must preserve conclusions, not prose.
/// Vault values are never in the materials, and the instruction forbids
/// inventing findings beyond the registry (the registry itself is
/// re-injected verbatim every turn, so the summary cannot corrupt it).
const COMPACT_FORK_INSTRUCTION: &str = r#"CONTEXT COMPACTION OVERRIDE: ignore the RESPONSE CONTRACT for this message only — output a prose summary below, not a JSON decision. The conversation above outgrew the context window.

Write a dense structured summary (~1500 words):

1. GOAL + TARGET — what is being assessed.
2. WHAT WAS TRIED — tools/capabilities run and what each learned (1 line each).
3. CURRENT UNDERSTANDING — hypotheses, validated paths, dead ends.
4. PENDING NEXT STEPS — what to try next and why.
5. LAST ERROR — only if one is present.

Rules:
- The brief's FINDINGS REGISTRY is authoritative: carry every finding over faithfully (ids, severities, statuses). NEVER invent findings beyond it.
- Carry VAULT KEY NAMES over (you do not have the values; never ask for them to be repeated here).
- Preserve concrete facts (hosts, ports, paths, versions, exact error strings); drop chit-chat and intermediate reasoning.
- Plain text, no JSON, no markdown headers beyond the numbered sections."#;

/// Why a turn or investigation ended.
#[derive(Debug, Clone)]
pub enum DriveOutcome {
    /// Model answered the user (interactive sessions only).
    Replied(String),
    /// Model declared the assessment complete.
    Finished(String),
    /// Step budget exhausted (per-turn in interactive mode).
    MaxSteps(usize),
    Cancelled,
    TooManyModelErrors {
        count: usize,
        last_error: String,
    },
    ConfigError(String),
    /// The context window stayed exhausted across a compaction (even a
    /// fresh summary cannot fit): the turn ends gracefully with findings
    /// and vault intact instead of thrashing.
    ContextExhausted,
}

/// One interactive session: persistent context and scope across turns.
/// Created via [`AgentRuntime::session`]; the runtime stays stateless so
/// several sessions can share one process (desktop actor model: one
/// `AgentSession` per conversation worker).
pub struct AgentSession<'r, 'a> {
    rt: &'r AgentRuntime<'a>,
    /// Owned env clone: held so provider selection and the
    /// available-capability list stay honest about the original scan
    /// state without mutating the shared environment snapshot.
    env: EnvironmentState,
    cm: ContextManager,
    /// Authoritative security state (TargetModel + graph + findings +
    /// evidence + family progress + objectives). Persisted per assessment;
    /// ContextManager only projects views from it.
    assessment: AssessmentState,
    tool_results: Vec<ToolResult>,
    consecutive_errors: usize,
    /// Consecutive SLOW-burn LLM failures (full-budget timeouts, stalls,
    /// rate limits). Gives up after [`LLM_MAX_SLOW_RETRIES`] instead of
    /// riding out all 5 tries — two burned budgets in a row means the
    /// endpoint is wedged, not flapping. Reset on any success.
    consecutive_slow_errors: usize,
    step: usize,
    /// Monotonic id for hypothesis events (event-only: the model's
    /// reasoning, not a store we rank).
    hypothesis_seq: usize,
    policy: ExecutionPolicy,
    scope_label: String,
    /// Set after the user denied (or never answered) a high-risk approval:
    /// further high-risk rejections don't block again — the model gets the
    /// feedback and pivots. Cleared on a fresh approval.
    approval_denied: bool,
    /// Cumulative LLM seconds for the step in flight. Failed/retried
    /// model calls accumulate here; consumed (taken) when the decision's
    /// events are emitted so the UI can attribute latency honestly.
    model_secs_step: f64,
    /// Latest context-window usage in tokens (provider `usage` when
    /// reported, char/4 estimate otherwise). Drives the context meter
    /// and auto-compaction.
    used_tokens: u64,
    /// Loop iterations since the last compaction. Guards against
    /// auto-compact thrashing: re-crossing the threshold with fewer
    /// than `MIN_STEPS_BETWEEN_COMPACTIONS` decisions of progress ends
    /// the turn instead of compacting again.
    steps_since_compact: usize,
    /// Per-target vault, loaded lazily once scope exists. `None` until
    /// the first vault decision (vaults are per-target; an unscoped
    /// session has nowhere to store).
    vault: Option<VaultManager>,
    /// Consecutive completion denials. Caps gating loops: after
    /// MAX_FINISH_DENIES the proposal is accepted so a stubborn model
    /// cannot spin forever (termination safety; still surfaced via events).
    finish_denies: usize,
    /// Consecutive decision-level execution failures for one request
    /// signature (repeat-failure circuit breaker). The signature covers
    /// capability + target + normalized argument SHAPE (option names and
    /// value lengths, never values), so a retry with changed arguments
    /// is a different request and allowed — only byte-equivalent repeats
    /// trip the breaker.
    repeat_fail_sig: String,
    repeat_fail_count: u32,
    /// Assessment state version (observations + findings) at the last
    /// failure. New evidence re-arms one retry of the same signature:
    /// the world changed, so the outcome might too.
    repeat_fail_state: usize,
    /// First line of the most recent failure for this signature.
    repeat_fail_last: String,
    /// Breaker trips for the current signature. Caps the block loop:
    /// a model that retries the identical failing request past the
    /// remediation ends the turn instead of burning calls forever.
    breaker_trips: u32,
}

/// Canonical signature of a request for repeat detection:
/// `capability|target|opt1=kind[,opt2=...]` with options sorted by name
/// and values reduced to kind+length (headers reduce to sorted names).
/// Two decisions with equal signatures would send equivalent requests.
fn request_signature(request: &CapabilityRequest) -> String {
    let mut parts: Vec<String> = vec![request.capability.clone(), request.target.clone()];
    let mut opts: Vec<String> = request
        .options
        .iter()
        .map(|(k, v)| {
            let shape = match v {
                super::model::OptionValue::Str(s) => {
                    format!("str:{}", s.chars().count())
                }
                super::model::OptionValue::Num(n) => format!("num:{n}"),
                super::model::OptionValue::Bool(b) => format!("bool:{b}"),
                super::model::OptionValue::Map(m) => {
                    format!("map:{}", m.keys().cloned().collect::<Vec<_>>().join(","))
                }
            };
            format!("{k}={shape}")
        })
        .collect();
    opts.sort();
    parts.extend(opts);
    parts.join("|")
}

/// Decisions of progress required between two auto-compactions.
const MIN_STEPS_BETWEEN_COMPACTIONS: usize = 2;

/// Attempts per execute decision before the failure is reported to the
/// model. Transient blips (fast exits, network hiccups) recover here;
/// timeouts are never retried (they already burned the full budget).
const MAX_ATTEMPTS: usize = 3;

impl<'r, 'a> AgentSession<'r, 'a> {
    /// Interactive turn: user message in, terminal Reply event out.
    /// Executes tools in between as the model decides. Guarantees exactly
    /// one terminal event per completed turn (`Reply` — or none when the
    /// turn was cancelled).
    pub fn run_turn(
        &mut self,
        user_message: &str,
        emit: &mut dyn FnMut(AgentEvent),
    ) -> DriveOutcome {
        use super::events::AgentEvent as Ev;

        // A Stop applies to the turn in flight only: clear any previous
        // cancellation so a fresh user message always gets a working
        // turn. (Autonomous `investigate` deliberately does NOT reset —
        // a pre-cancelled run must stay cancelled.)
        self.rt.handle.reset();
        // Fresh turn: nothing is disabled. Tools are never taken away
        // from the model — it has full visibility of what already ran
        // (prior_actions) and decides when to retry. Removing tools was
        // the original loop hazard: without that hindsight the model kept
        // re-running a failing tool, so we removed the tool instead of
        // fixing the visibility.
        self.grant_scope_from_message(user_message, emit);
        self.cm.begin_turn(user_message);
        // Interactive mode for the brief; a fresh turn drops any staged
        // model note left over from a previous turn.
        self.cm.set_autonomous(false);
        self.cm.clear_staged_model_note();
        let outcome = self.drive(false, emit);
        self.trace(
            crate::infra::trace::tag::TURN_END,
            format!("turn ended: {}", drive_outcome_kind(&outcome)),
            serde_json::json!({
                "outcome": drive_outcome_kind(&outcome),
                "step": self.step,
            }),
        );
        match &outcome {
            DriveOutcome::Replied(text) => {
                let text = text.clone();
                self.cm.end_turn(&text);
                // The reply is user-facing speech too — record it so the
                // next turn knows what was already said.
                self.cm.add_narration(&text);
                emit(Ev::Reply { text });
            }
            DriveOutcome::Finished(reason) => {
                let reason = reason.clone();
                self.cm.end_turn(&reason);
                self.cm.push_assistant(reason.clone());
                emit(Ev::Finished {
                    reason: reason.clone(),
                });
                emit(Ev::Reply { text: reason });
            }
            DriveOutcome::MaxSteps(n) => {
                let text = format!(
                    "I hit the per-turn step limit ({n}). Ask me to continue and I'll pick up where I left off."
                );
                self.cm.end_turn(&text);
                self.cm.push_assistant(text.clone());
                emit(Ev::Reply { text });
            }
            DriveOutcome::TooManyModelErrors { count, last_error } => {
                // Worded neutrally on purpose: the budget covers BOTH
                // unreachable-model (transport) and reachable-but-
                // unparseable-model (bad responses) failures — saying
                // "couldn't reach" misdiagnoses the latter.
                let text =
                    format!("The model step failed {count} times in a row and I stopped: {last_error}");
                self.cm.end_turn(&text);
                self.cm.push_assistant(text.clone());
                // A give-up ends the turn: no staged note may leak into
                // the next turn's tail.
                self.cm.clear_staged_model_note();
                emit(Ev::Reply { text });
            }
            DriveOutcome::ConfigError(e) => {
                let text = format!("Model configuration problem: {e}");
                self.cm.end_turn(&text);
                self.cm.push_assistant(text.clone());
                emit(Ev::Reply { text });
            }
            DriveOutcome::ContextExhausted => {
                let text = "My context filled up and even a compacted summary can't fit what remains — I've kept every finding and vault key, so nothing confirmed is lost. Start a new turn or session and I'll continue from the registry.".to_string();
                self.cm.end_turn(&text);
                self.cm.push_assistant(text.clone());
                emit(Ev::Reply { text });
            }
            DriveOutcome::Cancelled => {}
        }
        outcome
    }

    /// Grant scope for every host-like token the user mentioned. WE parse
    /// the message — the model can never grant scope. Emits `ScopeGranted`
    /// per newly added root so UIs can show the live scope.
    fn grant_scope_from_message(&mut self, message: &str, emit: &mut dyn FnMut(AgentEvent)) {
        for host in hosts_in(message) {
            if self.policy.grant_scope(&host) {
                self.scope_label = host.clone();
                emit(AgentEvent::ScopeGranted { target: host.clone() });
                self.trace(
                    crate::infra::trace::tag::SCOPE_GRANT,
                    format!("scope granted: {host}"),
                    serde_json::json!({
                        "host": host,
                        "scope_label": self.scope_label,
                    }),
                );
            }
        }
        // Late grants (message after the first) still update the label.
        if self.scope_label.is_empty() {
            if let Some(first) = self.policy_scope_first() {
                self.scope_label = first;
            }
        }
    }

    fn policy_scope_first(&self) -> Option<String> {
        let roots = self.policy.scope_roots();
        roots.first().cloned()
    }

    /// Current window usage as a 0-100 percent, capped (estimates can
    /// overshoot the configured window).
    fn usage_pct(&self) -> u8 {
        let limit = self.rt.context_tokens.max(1);
        ((self.used_tokens.saturating_mul(100) / limit).min(100)) as u8
    }

    fn over_threshold(&self) -> bool {
        self.usage_pct() >= self.rt.compaction_threshold_pct
    }

    /// The session's vault, loaded lazily per scope target. Vaults are
    /// per-target: an unscoped session has nowhere to store.
    fn vault_mut(&mut self) -> Result<&mut VaultManager, String> {
        if self.scope_label.trim().is_empty() {
            return Err(
                "no assessment target in scope yet — the vault is per-target, tell me what to assess first"
                    .to_string(),
            );
        }
        let stale = match &self.vault {
            Some(v) => v.target() != self.scope_label,
            None => true,
        };
        if stale {
            self.vault = Some(VaultManager::load(&self.scope_label));
        }
        Ok(self.vault.as_mut().expect("vault just loaded"))
    }

    fn vault_key_lines(&self) -> Vec<String> {
        self.vault
            .as_ref()
            .filter(|v| v.target() == self.scope_label)
            .map(|v| v.key_lines())
            .unwrap_or_default()
    }

    fn refresh_vault_keys(&mut self) {
        let keys = self.vault_key_lines();
        self.cm.set_vault_keys(keys);
    }

    /// Resolve `{{vault:key}}` references in tool options against the
    /// session vault, out of band at execution time. Fast path: options
    /// without references return cloned without touching the vault (an
    /// unavailable vault is then not an error either).
    fn resolve_vault_refs_in_options(
        &mut self,
        options: &super::model::OptionSet,
    ) -> Result<super::model::OptionSet, String> {
        if !super::model::options_contain_vault_refs(options) {
            return Ok(options.clone());
        }
        match self.vault_mut() {
            Ok(vault) => super::model::substitute_vault_refs(options, &|k| {
                vault.recall(k).ok().map(|(_, val)| val.to_string())
            }),
            Err(e) => Err(e),
        }
    }

    /// Text variant for direct tools (file content). Same contract.
    fn resolve_vault_refs_in_text(&mut self, text: &str) -> Result<String, String> {
        if !text.contains("{{vault:") {
            return Ok(text.to_string());
        }
        match self.vault_mut() {
            Ok(vault) => super::model::substitute_vault_refs_in_text(text, &|k| {
                vault.recall(k).ok().map(|(_, val)| val.to_string())
            }),
            Err(e) => Err(e),
        }
    }

    /// Bump family progress for fresh evidence (marks InProgress/Tested,
    /// counts evidence, emits nothing — callers emit the progress event).
    fn mark_family_evidence(&mut self, family: &str) {
        let progress = if let Some(p) = self
            .assessment
            .family_progress
            .iter_mut()
            .find(|p| p.family == family)
        {
            p.evidence_count += 1;
            p.tested_questions = (p.tested_questions + 1).min(p.total_questions.max(1));
            p.status = super::completeness::AssessmentStatus::InProgress;
            Some((
                p.tested_questions,
                p.total_questions,
                p.evidence_count,
                format!("{:?}", p.status),
            ))
        } else {
            None
        };
        if let Some((tested, total, evidence, status)) = progress {
            self.trace(
                crate::infra::trace::tag::STATE_FAMILY,
                format!("family {family} +evidence ({tested}/{total})"),
                serde_json::json!({
                    "family": family,
                    "status": status,
                    "evidence_count": evidence,
                }),
            );
        }
    }

    /// Best-effort snapshot after each state mutation. Never fails the
    /// loop: a full disk or poisoned path must not kill an assessment.
    fn persist_best_effort(&mut self) {
        self.assessment.touch(super::assessment::now_unix(), self.step);
        // `scope_label` and the policy's granted roots are otherwise
        // in-memory-only (ExecutionPolicy is never itself serialized):
        // without syncing them here, a session resumed from this
        // snapshot would regain the world model and findings but have
        // NO scope at all, rejecting every subsequent action.
        self.assessment.target_roots = self.policy.scope_roots();
        self.assessment.scope_label = self.scope_label.clone();
        let saved = super::assessment::save(&self.assessment);
        // The ContextManager snapshot is the other half of a full resume
        // (see `resume_session_with_context`): without it, a reopened
        // session regains the world model but not prior_actions, raw
        // evidence, or the error history — all pure ContextManager state
        // the assessment snapshot never carried.
        let cm_saved = super::context::save(&self.assessment.id, &self.cm);
        self.trace(
            crate::infra::trace::tag::STATE_SNAPSHOT,
            format!(
                "snapshot {} step {} {} (context {})",
                self.assessment.id,
                self.step,
                if saved.is_ok() { "ok" } else { "FAILED" },
                if cm_saved.is_ok() { "ok" } else { "FAILED" }
            ),
            serde_json::json!({
                "assessment": self.assessment.id,
                "ok": saved.is_ok(),
                "context_ok": cm_saved.is_ok(),
            }),
        );
    }

    /// Append one debug-trace line (no-op when no tracer is attached).
    /// Values are scrubbed inside [`TraceEntry::new`]; callers pass the
    /// natural payload and must still avoid vault values / bodies.
    fn trace(&self, tag: &str, msg: String, data: serde_json::Value) {
        if let Some(tracer) = self.rt.tracer.borrow_mut().as_mut() {
            tracer(crate::infra::trace::TraceEntry::new(
                self.step,
                &self.assessment.id,
                tag,
                msg,
                data,
            ));
        }
    }

    /// Monotonic assessment-state version for the breaker: observations
    /// + findings + evidence records. When it advances, the world changed
    /// and one retry of a previously failed signature is allowed.
    fn state_version(&self) -> usize {
        self.cm.observations().len()
            + self.cm.findings().len()
            + self.assessment.evidence.records.len()
    }

    /// Record a decision-level execution outcome for the repeat-failure
    /// breaker. Success (or a different signature) resets the streak.
    /// `detail` is the failure's first line, kept for remediation text
    /// (the ContextManager error is cleared before the next decision).
    fn note_execution_outcome(
        &mut self,
        request: &CapabilityRequest,
        success: bool,
        detail: &str,
    ) {
        let sig = request_signature(request);
        if success {
            self.repeat_fail_sig.clear();
            self.repeat_fail_count = 0;
            self.breaker_trips = 0;
            self.repeat_fail_last.clear();
        } else if self.repeat_fail_sig == sig {
            self.repeat_fail_count = self.repeat_fail_count.saturating_add(1);
            self.repeat_fail_last = detail.chars().take(200).collect();
            self.repeat_fail_state = self.state_version();
        } else {
            self.repeat_fail_sig = sig;
            self.repeat_fail_count = 1;
            self.breaker_trips = 0;
            self.repeat_fail_last = detail.chars().take(200).collect();
            self.repeat_fail_state = self.state_version();
        }
    }

    /// Char/4 estimate of the live window: conversation + observations +
    /// findings + vault keys + narrations. Used after a compaction (the
    /// provider's next `usage` block takes over from there).
    fn estimate_window_tokens(&self) -> u64 {
        let conv: usize = self
            .cm
            .conversation()
            .iter()
            .map(|t| t.user.len() + t.assistant.len())
            .sum();
        let obs: usize = self.cm.observations().iter().map(|o| o.summary.len()).sum();
        let fnd: usize = self
            .cm
            .findings()
            .iter()
            .map(|f| f.title.len() + f.detail.len())
            .sum();
        ((conv + obs + fnd) / 4) as u64 + 512
    }

    /// Replace older turns with a model-written summary (or oldest-first
    /// truncation when the summarizer call fails). Findings, vault keys,
    /// narrations, and recent turns survive verbatim.
    ///
    /// The summarizer runs as a cache-reading FORK: the parent's exact
    /// message array (system + brief + transcript + tail) with the
    /// compaction instruction appended. From the gateway's perspective
    /// this is nearly identical to the last request, so the cached
    /// prefix is reused at read price instead of a full re-prefill.
    /// Same SYSTEM_PROMPT throughout — a different system prompt would
    /// invalidate the whole prefix.
    fn run_compaction(&mut self, emit: &mut dyn FnMut(AgentEvent)) {
        use super::events::AgentEvent as Ev;
        let before = self.used_tokens;
        let keep = self.rt.compact_keep_turns;
        let target = Target::new(&self.scope_label);
        let view = self
            .rt
            .context_view(&self.env, &target, self.step, &self.cm);
        let mut messages =
            super::model::render_chat_messages(&view.brief, &view.transcript, &view.tail);
        messages.push(serde_json::json!({
            "role": "user",
            "content": COMPACT_FORK_INSTRUCTION,
        }));
        self.trace(
            crate::infra::trace::tag::LLM_CHAT,
            format!(
                "compaction fork: {} parent messages + instruction",
                messages.len().saturating_sub(1)
            ),
            serde_json::json!({"purpose": "compact", "messages": messages.len()}),
        );
        match self.rt.model.borrow().chat_messages(
            super::model::SYSTEM_PROMPT,
            &messages,
        ) {
            Ok(summary) => {
                self.cm.compact(&summary, keep);
                self.refresh_vault_keys();
                let after = self.estimate_window_tokens();
                self.used_tokens = after;
                emit(Ev::Compacted {
                    before_tokens: before,
                    after_tokens: after,
                    freed_tokens: before.saturating_sub(after),
                    fallback: false,
                });
                self.trace(
                    crate::infra::trace::tag::CONTEXT_COMPACTED,
                    format!("compacted {before} -> {after} tokens"),
                    serde_json::json!({
                        "before_tokens": before,
                        "after_tokens": after,
                        "summary_chars": summary.len(),
                        "fallback": false,
                    }),
                );
            }
            Err(e) => {
                // The summarizer failed (transport, bad response): degrade
                // to oldest-first truncation. The registry and vault keys
                // are still intact — only prose history is lost.
                self.cm.compact(
                    &format!(
                        "(summarizer unavailable: {e}) Earlier turns truncated oldest-first; the findings registry and vault keys below are complete — trust them."
                    ),
                    keep,
                );
                self.refresh_vault_keys();
                let after = self.estimate_window_tokens();
                self.used_tokens = after;
                emit(Ev::Compacted {
                    before_tokens: before,
                    after_tokens: after,
                    freed_tokens: before.saturating_sub(after),
                    fallback: true,
                });
                self.trace(
                    crate::infra::trace::tag::CONTEXT_COMPACTED,
                    format!("compaction fallback {before} -> {after} tokens"),
                    serde_json::json!({
                        "before_tokens": before,
                        "after_tokens": after,
                        "fallback": true,
                    }),
                );
            }
        }
    }

    /// Manual compaction (desktop "Compact now"): same path as
    /// auto-compaction, unconditional.
    pub fn compact_now(&mut self, emit: &mut dyn FnMut(AgentEvent)) {
        self.run_compaction(emit);
        self.steps_since_compact = 0;
    }

    /// Re-grant scope from the session log's `Rec::Target` entries only —
    /// safe to call after a snapshot-based resume (unlike full
    /// [`Self::rehydrate`], which would duplicate the conversation and
    /// narrations the snapshot already carries). A defensive backstop
    /// for a snapshot saved before `persist_best_effort` started syncing
    /// `scope_label`/`target_roots` onto `AssessmentState`: if the
    /// resumed session still has no scope, this recovers it from the
    /// log instead of leaving the session permanently unable to act.
    pub fn restore_scope_from_log(&mut self, records: &[crate::infra::sessions::TimedRecord]) {
        if !self.scope_label.is_empty() {
            return;
        }
        use crate::infra::sessions::SessionRecord as Rec;
        for timed in records {
            if let Rec::Target { target } = &timed.record {
                self.policy.grant_scope(target);
                self.scope_label = target.clone();
            }
        }
    }

    /// Rebuild live model state (scope, conversation, observations) from a
    /// persisted session file. Without this, reopening a session after an
    /// app restart shows the transcript in the UI while the model starts
    /// blank: no target in scope, no memory of prior turns or findings, so
    /// a follow-up like "try other severities" has nothing to point at.
    /// Replaying is silent (no events — the UI already has the records)
    /// and idempotent (grants and observations dedupe).
    pub fn rehydrate(&mut self, records: &[crate::infra::sessions::TimedRecord]) {
        use crate::infra::sessions::SessionRecord as Rec;
        for timed in records {
            match &timed.record {
                Rec::Target { target } => {
                    self.policy.grant_scope(target);
                    self.scope_label = target.clone();
                }
                Rec::Chat { user, agent, .. } => {
                    // Dedupe: replaying a file twice (or a crash-resume
                    // retry) must not stack duplicate turns.
                    let seen = self
                        .cm
                        .last_turn()
                        .is_some_and(|t| t.user == *user && t.assistant == *agent);
                    if !seen {
                        self.cm.begin_turn(user);
                        self.cm.end_turn(agent);
                    }
                }
                Rec::Obs { text } => {
                    let target = self.scope_label.clone();
                    let step = self.step;
                    self.cm.add_observation(&target, text, "replay", step);
                }
                Rec::Note { text } => {
                    // Replayed narrations keep the model aware of what
                    // the user was already told in prior sessions.
                    self.cm.add_narration(text);
                }
                Rec::Finding {
                    id,
                    severity,
                    title,
                    target,
                    status,
                    detail,
                    step,
                } => {
                    // Registry rows replay verbatim (records are
                    // chronological, so a later row for the same id
                    // carries the newer status). Double-load safe.
                    if self.cm.findings().iter().any(|f| f.id == *id) {
                        self.cm.update_finding(*id, status, *step);
                    } else {
                        self.cm.replay_finding(Finding {
                            id: *id,
                            severity: severity.clone(),
                            title: title.clone(),
                            target: target.clone(),
                            source: "replay".into(),
                            detail: detail.clone(),
                            status: status.clone(),
                            step_found: *step,
                            step_updated: *step,
                        });
                    }
                    // Mirror into authoritative store (idempotent by
                    // title+target); status maps onto the lifecycle.
                    let family = super::families::infer_family(title, detail).to_string();
                    let tracked = match self
                        .assessment
                        .findings
                        .findings
                        .iter()
                        .find(|f| f.title == *title && f.target == *target)
                        .map(|f| f.id)
                    {
                        Some(existing) => existing,
                        None => self.assessment.findings.create(title, target, &family, severity),
                    };
                    let norm = status.trim().to_lowercase();
                    if norm == "confirmed" {
                        self.assessment
                            .findings
                            .promote_toward_validated(tracked, "replayed confirmed");
                    } else if norm == "false_positive" || norm == "false-positive" {
                        if let Some(f) = self.assessment.findings.get_mut(tracked) {
                            let _ = f.transition(super::findings::FindingStage::Closed, "replayed");
                        }
                    }
                }
                Rec::CtxUsage { used, .. } => {
                    // Resume the meter where the session left off so a
                    // reopened long session compacts on schedule.
                    self.used_tokens = *used;
                }
                Rec::Compacted { .. } => {
                    // A compaction happened in a prior process lifetime:
                    // keep the continuity note; the summary itself was
                    // already folded into the replayed conversation.
                    self.cm.note_replayed_compaction();
                }
                Rec::VaultOp { .. } => {
                    // Vault state loads from disk on demand — nothing to
                    // replay (and values are never in records by design).
                }
                _ => {}
            }
        }
    }

    /// Direct `file_read` implementation: resolve the model's path to a
    /// confined location and read a bounded slice of it. Rather than
    /// dumping a large file into context, `grep` returns only matching
    /// lines (with context) and a plain read returns a head window. This
    /// keeps a big file (bundle.js, logs) from blowing the budget.
    fn run_file_read(
        &mut self,
        path: &str,
        grep: &Option<String>,
        lines: &Option<u32>,
        reason: &str,
        model_secs: f64,
        emit: &mut dyn FnMut(AgentEvent),
    ) {
        use super::events::AgentEvent as Ev;
        use super::file_tools::{grep_file, read_n_lines, ReadSlice};
        let roots = self.policy.scope_roots();
        emit(Ev::CapabilityRequested {
            capability: "file.read".into(),
            target: path.to_string(),
            reason: reason.to_string(),
            model_secs,
        });
        match super::file_tools::resolve_path(path, &roots) {
            Err(e) => {
                let msg = format!("file read not allowed for \"{path}\": {e}");
                emit(Ev::ToolExecuted {
                    tool_id: "file-read".into(),
                    capability: "file.read".into(),
                    target: path.to_string(),
                    exit_code: 1,
                    success: false,
                    timed_out: false,
                    output: msg.clone(),
                    tool_secs: 0.0,
                });
                self.cm.set_last_error(Some(msg.clone()));
                self.trace(
                    crate::infra::trace::tag::DECISION_FILE_READ,
                    format!("file read rejected: {path}"),
                    serde_json::json!({"path": path, "ok": false, "reason": msg}),
                );
            }
            Ok(real) => {
                // Wall-clock for the operation (read/grep slice) so the
                // UI's duration chip shows why an op was slow.
                let t0 = std::time::Instant::now();
                let sliced: Result<ReadSlice, String> = if let Some(pat) = grep {
                    grep_file(&real, pat)
                } else {
                    let n = lines
                        .map(|l| l as usize)
                        .unwrap_or(super::file_tools::DEFAULT_READ_LINES);
                    read_n_lines(&real, n)
                };
                match sliced {
                    Ok(slice) => {
                        let body = slice.lines.join("\n");
                        let total = slice.total_lines;
                        let returned = slice.lines.len();
                        let elided = total.saturating_sub(returned);
                        let mode = if grep.is_some() {
                            "match"
                        } else {
                            "window"
                        };
                        let evidence = serde_json::json!({
                            "tool": "file-read",
                            "path": real.display().to_string(),
                            "mode": mode,
                            "total_lines": total,
                            "returned_lines": returned,
                            "elided_lines": elided,
                            "complete": slice.complete,
                            "content": body,
                        });
                        emit(Ev::ToolExecuted {
                            tool_id: "file-read".into(),
                            capability: "file.read".into(),
                            target: path.to_string(),
                            exit_code: 0,
                            success: true,
                            timed_out: false,
                            output: serde_json::to_string(&evidence).unwrap_or_default(),
                            tool_secs: t0.elapsed().as_secs_f64(),
                        });
                        // CRITICAL: ride the raw content into the model's
                        // `recent_evidence` on the next step — WITHOUT this,
                        // the UI shows "file-read ok" but the model never
                        // sees the lines it read, so it has nothing to work
                        // from and keeps re-reading the same file.
                        self.cm.add_evidence("file-read", path, &body);
                        let step = self.step;
                        let summary = if returned == 0 {
                            format!(
                                "{} ({} lines): no lines matched the grep",
                                real.display(),
                                total
                            )
                        } else {
                            format!(
                                "{}: {} lines returned{}",
                                real.display(),
                                returned,
                                if elided > 0 {
                                    format!(" of {total}, {elided} elided")
                                } else {
                                    " (complete)".to_string()
                                }
                            )
                        };
                        self.cm.add_observation(&path, &summary, "file.read", step);
                        emit(Ev::ObservationAdded { summary: summary.clone() });
                        self.trace(
                            crate::infra::trace::tag::DECISION_FILE_READ,
                            format!("file read ok: {path} ({returned}/{total} lines)"),
                            serde_json::json!({
                                "path": path,
                                "mode": mode,
                                "total_lines": total,
                                "returned_lines": returned,
                                "elided_lines": elided,
                            }),
                        );
                    }
                    Err(e) => {
                        let msg = format!("file read failed: {e}");
                        emit(Ev::ToolExecuted {
                            tool_id: "file-read".into(),
                            capability: "file.read".into(),
                            target: path.to_string(),
                            exit_code: 1,
                            success: false,
                            timed_out: false,
                            output: msg.clone(),
                            tool_secs: t0.elapsed().as_secs_f64(),
                        });
                        self.cm.set_last_error(Some(msg.clone()));
                        self.trace(
                            crate::infra::trace::tag::DECISION_FILE_READ,
                            format!("file read failed: {path}"),
                            serde_json::json!({"path": path, "ok": false, "reason": msg}),
                        );
                    }
                }
            }
        }
    }

    /// Direct `file_write` implementation: resolve to a confined location
    /// (creating the work dir), write the content, and confirm to the
    /// model. Confinement takes precedence — a refused path is never
    /// written anywhere.
    fn run_file_write(
        &mut self,
        path: &str,
        content: &str,
        reason: &str,
        model_secs: f64,
        emit: &mut dyn FnMut(AgentEvent),
    ) {
        use super::events::AgentEvent as Ev;
        let roots = self.policy.scope_roots();
        emit(Ev::CapabilityRequested {
            capability: "file.write".into(),
            target: path.to_string(),
            reason: reason.to_string(),
            model_secs,
        });
        match super::file_tools::resolve_path(path, &roots) {
            Err(e) => {
                let msg = format!("file write not allowed for \"{path}\": {e}");
                emit(Ev::ToolExecuted {
                    tool_id: "file-write".into(),
                    capability: "file.write".into(),
                    target: path.to_string(),
                    exit_code: 1,
                    success: false,
                    timed_out: false,
                    output: msg.clone(),
                    tool_secs: 0.0,
                });
                self.cm.set_last_error(Some(msg.clone()));
                self.trace(
                    crate::infra::trace::tag::DECISION_FILE_WRITE,
                    format!("file write rejected: {path}"),
                    serde_json::json!({"path": path, "ok": false, "reason": msg}),
                );
            }
            Ok(real) => {
                let t0 = std::time::Instant::now();
                match super::file_tools::write_file(&real, content) {
                Ok(bytes) => {
                    let wrapped = match serde_json::to_string(&serde_json::json!({
                        "tool": "file-write",
                        "path": real.display().to_string(),
                        "bytes": bytes,
                    })) {
                        Ok(s) => s,
                        Err(_) => real.display().to_string(),
                    };
                    emit(Ev::ToolExecuted {
                        tool_id: "file-write".into(),
                        capability: "file.write".into(),
                        target: path.to_string(),
                        exit_code: 0,
                        success: true,
                        timed_out: false,
                        output: wrapped,
                        tool_secs: t0.elapsed().as_secs_f64(),
                    });
                    let step = self.step;
                    let summary =
                        format!("wrote {} ({} bytes)", real.display(), bytes);
                    self.cm.add_observation(&path, &summary, "file.write", step);
                    emit(Ev::ObservationAdded { summary: summary.clone() });
                    self.trace(
                        crate::infra::trace::tag::DECISION_FILE_WRITE,
                        format!("file write ok: {path} ({bytes} bytes)"),
                        serde_json::json!({"path": path, "bytes": bytes}),
                    );
                }
                Err(e) => {
                    let msg = format!("file write failed: {e}");
                    emit(Ev::ToolExecuted {
                        tool_id: "file-write".into(),
                        capability: "file.write".into(),
                        target: path.to_string(),
                        exit_code: 1,
                        success: false,
                        timed_out: false,
                        output: msg.clone(),
                        tool_secs: t0.elapsed().as_secs_f64(),
                    });
                    self.cm.set_last_error(Some(msg.clone()));
                    self.trace(
                        crate::infra::trace::tag::DECISION_FILE_WRITE,
                        format!("file write failed: {path}"),
                        serde_json::json!({"path": path, "ok": false, "reason": msg}),
                    );
                }
                }
            }
        }
    }

    /// Block until the user answers the approval dialog (interactive UIs).
    /// `Some(true)` latches the destructive flag so the model's retry
    /// passes validation; deny/timeout leave it off. Cancel-aware.
    fn wait_for_approval(&mut self) -> ApprovalDecision {
        let Some(gate) = self.rt.approval_gate.clone() else {
            return ApprovalDecision::None;
        };
        const TIMEOUT_MS: u64 = 180_000;
        const POLL_MS: u64 = 150;
        let mut waited = 0u64;
        loop {
            if self.rt.handle.is_cancelled() {
                return ApprovalDecision::None;
            }
            let decision = { gate.lock().unwrap().take() };
            match decision {
                Some(true) => {
                    self.policy.allow_destructive.store(true, Ordering::SeqCst);
                    return ApprovalDecision::Allow;
                }
                Some(false) => return ApprovalDecision::Deny,
                None => {}
            }
            if waited >= TIMEOUT_MS {
                return ApprovalDecision::None;
            }
            std::thread::sleep(std::time::Duration::from_millis(POLL_MS));
            waited += POLL_MS;
        }
    }

    /// The shared decision loop. `autonomous = true` drives to
    /// Finish/limits (CLI `assess`); `false` additionally stops on Reply.
    fn drive(&mut self, autonomous: bool, emit: &mut dyn FnMut(AgentEvent)) -> DriveOutcome {
        use super::events::AgentEvent as Ev;

        // Production default shares the cancel flag so a Stop kills the
        // in-flight child within one poll tick instead of blocking the
        // whole turn on a slow/hung subprocess. An injected executor
        // (tests) is used as-is.
        let executor: Arc<dyn ProcessExecutor> = self.rt.executor.clone().unwrap_or_else(|| {
            Arc::new(LocalProcessExecutor::new().with_cancel(self.rt.handle.flag()))
        });
        let turn_start_step = self.step;
        loop {
            if self.rt.handle.is_cancelled() {
                self.trace(
                    crate::infra::trace::tag::SESSION_CANCELLED,
                    format!("turn cancelled at step {}", self.step),
                    serde_json::json!({"step": self.step}),
                );
                return DriveOutcome::Cancelled;
            }
            // Fold in any user messages that arrived mid-turn. They join
            // the SAME turn: appended to the conversation and run through
            // scope-granting, so the model sees them when it builds the
            // very next view and adapts — no stop, no fresh turn. Drained
            // at the top of the loop so an injected message is visible on
            // this iteration's decision, not one step later.
            if let Some(drain) = &self.rt.input_drain {
                for msg in drain() {
                    self.grant_scope_from_message(&msg, emit);
                    self.cm.inject_user_message(&msg);
                    self.trace(
                        crate::infra::trace::tag::SESSION_INPUT_INJECTED,
                        format!("mid-turn user message folded in at step {}", self.step),
                        serde_json::json!({"step": self.step, "message_len": msg.chars().count()}),
                    );
                    emit(Ev::UserMessageSeen { text: msg });
                }
            }
            // Apply a pending provider switch before the next LLM request,
            // so switching models mid-turn takes effect on the very next
            // step (Claude Code / Codex behavior) instead of waiting for the
            // turn to end. The new model inherits the cancel flag via
            // `swap_model`, and keeps the session's context/scope untouched.
            if let Some(reload) = &self.rt.model_reload {
                if let Some(model) = reload() {
                    let name = model.name().to_string();
                    self.rt.swap_model(model);
                    self.trace(
                        crate::infra::trace::tag::SESSION_MODEL_SWAPPED,
                        format!("model switched to {name} at step {}", self.step),
                        serde_json::json!({"step": self.step, "model": name}),
                    );
                    emit(Ev::Status {
                        message: format!("Switched model to {name}."),
                    });
                }
            }
            // Optional decision budget (None = unlimited): interactive
            // turns get a per-turn budget; autonomous runs a total budget.
            if let Some(limit) = self.rt.max_steps {
                let budget = if autonomous {
                    limit
                } else {
                    turn_start_step.saturating_add(limit)
                };
                if self.step >= budget {
                    return DriveOutcome::MaxSteps(limit);
                }
            }

            emit(Ev::StepStarted { step: self.step });
            // Auto-compaction BEFORE the view is built: when the last
            // reading crossed the threshold, older turns are summarized
            // so the next decision fits the window. Findings and vault
            // keys survive verbatim (see ContextManager::compact).
            self.steps_since_compact = self.steps_since_compact.saturating_add(1);
            if self.over_threshold() {
                if self.steps_since_compact < MIN_STEPS_BETWEEN_COMPACTIONS {
                    // Re-crossed with no progress in between: even a fresh
                    // summary cannot fit. End gracefully instead of
                    // thrashing (compact → still over → compact → ...).
                    emit(Ev::Error {
                        message: "context window exhausted even after compaction — findings and vault preserved".to_string(),
                    });
                    return DriveOutcome::ContextExhausted;
                }
                self.run_compaction(emit);
                self.steps_since_compact = 0;
                if self.over_threshold() {
                    emit(Ev::Error {
                        message: "context window exhausted even after compaction — findings and vault preserved".to_string(),
                    });
                    return DriveOutcome::ContextExhausted;
                }
            }
            emit(Ev::ModelThinking);
            let target = Target::new(&self.scope_label);
            let mut ctx = self
                .rt
                .context_view(&self.env, &target, self.step, &self.cm);
            // Project authoritative state (attack graph, families, unknowns)
            // into the LLM view. ContextManager stays a pure selector.
            {
                let (attack, families, unknowns, completion) =
                    self.assessment.project_context();
                ctx.attack_summary = attack.clone();
                ctx.family_progress = families.clone();
                ctx.unknowns = unknowns.clone();
                ctx.completion_note = completion.clone();
                // Volatile state projections ride the per-step tail (never
                // the cached prefix): recomputed live every step.
                if !attack.is_empty()
                    || !families.is_empty()
                    || !unknowns.is_empty()
                    || completion.is_some()
                {
                    ctx.tail.push_str("STATE PROJECTION (authoritative — trust over older transcript content):\n");
                    for line in &attack {
                        ctx.tail.push_str(&format!("attack: {line}\n"));
                    }
                    for line in &families {
                        ctx.tail.push_str(&format!("family: {line}\n"));
                    }
                    for line in &unknowns {
                        ctx.tail.push_str(&format!("unknown: {line}\n"));
                    }
                    if let Some(note) = completion {
                        ctx.tail.push_str(&format!("completion: {note}\n"));
                    }
                }
            }
            ctx.autonomous = autonomous;
            ctx.vault_keys = self.vault_key_lines();
            // Advisory planner ranking (logged, never executed by the
            // harness): what the deterministic side considers highest
            // value next to. The LLM still decides.
            {
                let candidates = super::planner::suggest(
                    &self.assessment.investigation,
                    &ctx.available_capabilities,
                    5,
                );
                self.trace(
                    crate::infra::trace::tag::PLANNER_SUGGEST,
                    format!("planner: {} candidates", candidates.len()),
                    serde_json::json!({
                        "candidates": candidates.iter().map(|c| serde_json::json!({
                            "objective_id": c.objective_id,
                            "family": c.family,
                            "capability": c.capability,
                            "priority": c.priority,
                        })).collect::<Vec<_>>(),
                    }),
                );
            }
            // Trace the exact model input shape (sizes + redacted shape).
            // The full prompt body is NOT stored: vault values ride the
            // view for exactly one decision and must never land on disk.
            self.trace(
                crate::infra::trace::tag::LLM_REQUEST,
                format!(
                    "llm request step {} ({} caps, {} obs)",
                    self.step,
                    ctx.available_capabilities.len(),
                    ctx.observations.len()
                ),
                serde_json::json!({
                    "provider": self.rt.model.borrow().name(),
                    "target": ctx.target,
                    "step": ctx.step,
                    "autonomous": ctx.autonomous,
                    "available_capabilities": ctx.available_capabilities,
                    "unavailable_count": ctx.unavailable_count,
                    "observations_n": ctx.observations.len(),
                    "narrations_n": ctx.narrations.len(),
                    "recent_evidence_n": ctx.recent_evidence.len(),
                    "prior_actions_n": ctx.prior_actions.len(),
                    "capability_schemas_n": ctx.capability_schemas.len(),
                    "findings_n": ctx.findings.len(),
                    "vault_keys": ctx.vault_keys,
                    "vault_values_n": ctx.vault_values.len(),
                    "attack_summary": ctx.attack_summary,
                    "family_progress": ctx.family_progress,
                    "unknowns": ctx.unknowns,
                    "has_last_error": ctx.last_error.is_some(),
                }),
            );
            let decision = {
                // LLM latency attribution: every model call (failed or
                // not) accumulates into the step's model_secs.
                let model_t0 = std::time::Instant::now();
                let (outcome, usage) = self.rt.model.borrow().decide_reported(&ctx);
                self.model_secs_step += model_t0.elapsed().as_secs_f64();
                // Context meter: the provider's usage block is
                // authoritative; the char/4 estimate fills in when the
                // endpoint omits it.
                self.used_tokens = usage.total_tokens;
                emit(Ev::ContextUsage {
                    used_tokens: usage.total_tokens,
                    limit_tokens: self.rt.context_tokens,
                    pct: self.usage_pct(),
                    estimated: usage.estimated,
                    cached_tokens: usage.cached_tokens,
                });
                match outcome {
                    Ok(d) => {
                        self.consecutive_errors = 0;
                        self.consecutive_slow_errors = 0;
                        self.cm.set_last_error(None);
                        // Assistant replay: every decision lands in the
                        // transcript verbatim, so the next step continues
                        // from its own prior outputs. Reply/Narrate travel
                        // as their natural text via add_narration later —
                        // pushing them here too would duplicate them.
                        if !matches!(
                            d,
                            Decision::Reply { .. } | Decision::Narrate { .. }
                        ) {
                            self.cm.push_assistant(
                                super::model::render_decision_for_transcript(&d),
                            );
                        }
                        let latency = model_t0.elapsed().as_secs_f64();
                        self.trace(
                            crate::infra::trace::tag::LLM_RESPONSE,
                            format!(
                                "llm response step {} in {:.1}s: {} (tokens {}/{})",
                                self.step,
                                latency,
                                decision_kind(&d),
                                usage.prompt_tokens,
                                usage.completion_tokens,
                            ),
                            serde_json::json!({
                                "latency_secs": latency,
                                "decision": decision_kind(&d),
                                "detail": decision_trace_detail(&d),
                                "usage": {
                                    "prompt_tokens": usage.prompt_tokens,
                                    "completion_tokens": usage.completion_tokens,
                                    "total_tokens": usage.total_tokens,
                                    "estimated": usage.estimated,
                                    // Key deliberately free of the trace
                                    // scrubber's sensitive fragments (which
                                    // is why it is NOT `cached_tokens`):
                                    // prefix-cache hits per call, the audit
                                    // signal for the cache-first context
                                    // architecture.
                                    "cached": usage.cached_tokens,
                                },
                            }),
                        );
                        d
                    }
                    Err(ModelError::Cancelled) => {
                        // Stop pressed mid-call: not a failure — no error
                        // count, no retry, no user-facing error card. The
                        // turn ends cancelled; the session survives.
                        self.trace(
                            crate::infra::trace::tag::TURN_END,
                            "model call cancelled mid-stream".to_string(),
                            serde_json::json!({
                                "latency_secs": model_t0.elapsed().as_secs_f64(),
                            }),
                        );
                        return DriveOutcome::Cancelled;
                    }
                    Err(ModelError::Transport(e)) | Err(ModelError::BadResponse(e)) => {
                        self.consecutive_errors += 1;
                        let latency = model_t0.elapsed().as_secs_f64();
                        let slow = super::model::is_slow_llm_error(&e);
                        if slow {
                            self.consecutive_slow_errors += 1;
                        }
                        // Slow burns give up early: consecutive full-budget
                        // timeouts/stalls/rate-limits mean the endpoint is
                        // wedged, not flapping — no point riding out all 5
                        // tries at minutes apiece.
                        let slow_give_up = slow
                            && self.consecutive_slow_errors
                                >= super::model::LLM_MAX_SLOW_RETRIES;
                        if self.consecutive_errors >= self.rt.max_consecutive_errors
                            || slow_give_up
                        {
                            emit(Ev::Error {
                                message: format!(
                                    "model failed {} times in a row: {e}",
                                    self.consecutive_errors
                                ),
                            });
                            self.trace(
                                crate::infra::trace::tag::LLM_GAVE_UP,
                                format!(
                                    "llm gave up after {} errors",
                                    self.consecutive_errors
                                ),
                                serde_json::json!({
                                    "count": self.consecutive_errors,
                                    "latency_secs": latency,
                                }),
                            );
                            self.cm.clear_staged_model_note();
                            return DriveOutcome::TooManyModelErrors {
                                count: self.consecutive_errors,
                                last_error: e,
                            };
                        }
                        // Visible retry feedback: a timed-out call otherwise
                        // looks like the agent froze (minutes of silent
                        // waiting). Show a short cause + attempt count.
                        let brief: String = e.chars().take(80).collect();
                        emit(Ev::Status {
                            message: format!(
                                "model call failed ({brief}) — retrying {}/{}",
                                self.consecutive_errors, self.rt.max_consecutive_errors
                            ),
                        });
                        self.trace(
                            crate::infra::trace::tag::LLM_RETRY,
                            format!(
                                "llm retry {}/{} after {:.1}s: {brief}",
                                self.consecutive_errors,
                                self.rt.max_consecutive_errors,
                                latency
                            ),
                            serde_json::json!({
                                "attempt": self.consecutive_errors,
                                "latency_secs": latency,
                            }),
                        );
                        // Pacing: a provider-honored Retry-After wins
                        // (capped — a hostile header must not stall a step
                        // for hours); else fast errors retry in 100ms and
                        // slow burns back off exponentially. Cancellation-
                        // aware in 50ms slices.
                        let backoff_ms = match super::model::parse_retry_after_secs(&e) {
                            Some(n) => {
                                n.min(super::model::LLM_MAX_RETRY_AFTER_SECS)
                                    .saturating_mul(1000)
                                    .max(100)
                            }
                            None => super::model::llm_retry_delay_ms(
                                self.consecutive_errors,
                                &e,
                            ),
                        };
                        for _ in 0..(backoff_ms / 50).max(1) {
                            if self.rt.handle.is_cancelled() {
                                break;
                            }
                            std::thread::sleep(std::time::Duration::from_millis(50));
                        }
                        if self.rt.handle.is_cancelled() {
                            return DriveOutcome::Cancelled;
                        }
                        // Byte-identical retry: the view is deliberately NOT
                        // amended (no last_error injection), so the retried
                        // request shares the failed one's prefix — and on a
                        // prefix-caching gateway it reuses the already-paid
                        // prefill instead of paying it twice. The failure is
                        // staged for the NEXT step's tail instead.
                        self.cm.stage_model_note(
                            format!(
                                "model call failed ({brief}) — retried {}/{} with the identical request",
                                self.consecutive_errors, self.rt.max_consecutive_errors
                            ),
                            self.step,
                        );
                        continue; // same step retried
                    }
                    Err(ModelError::MissingConfig(e)) => {
                        // Config errors never heal by retrying.
                        emit(Ev::Error { message: e.clone() });
                        self.trace(
                            crate::infra::trace::tag::LLM_MISCONFIGURED,
                            "llm misconfigured".to_string(),
                            serde_json::json!({}),
                        );
                        return DriveOutcome::ConfigError(e);
                    }
                }
            };

            // Hand the accumulated LLM time to this decision's events,
            // then start the next step's accumulation from zero.
            let model_secs = std::mem::take(&mut self.model_secs_step);
            // Recalled vault values ride exactly ONE decision: they were
            // staged by a vault_recall on the previous step and served in
            // the view just consumed. Clear before executing.
            self.cm.clear_vault_values();

            match decision {
                Decision::Finish { reason } => {
                    // Completeness gate: the LLM proposes, Cipher disposes.
                    // Backward-compatible: sessions with no seeded objectives
                    // (legacy tests) finish immediately, as do runs that have
                    // produced no evidence yet (nothing to gate on).
                    const MAX_FINISH_DENIES: usize = 5;
                    self.trace(
                        crate::infra::trace::tag::DECISION_FINISH_PROPOSED,
                        format!("finish proposed: {}", reason.chars().take(120).collect::<String>()),
                        serde_json::json!({"reason_len": reason.chars().count()}),
                    );
                    if self.assessment.investigation.objectives.is_empty()
                        && self.assessment.family_progress.is_empty()
                    {
                        return DriveOutcome::Finished(reason);
                    }
                    // Nothing normalized into authoritative state yet (failed
                    // runs, unparsed output): nothing to gate on. The raw
                    // evidence log always grows, so gate on the normalized
                    // graph instead. This keeps legacy loop tests green
                    // while real runs with parsed observations hit the gate.
                    if self.assessment.attack_graph.nodes.is_empty() {
                        return DriveOutcome::Finished(reason);
                    }
                    if self.finish_denies >= MAX_FINISH_DENIES {
                        emit(Ev::CompletionEvaluated {
                            allowed: true,
                            reason: "finish-denial budget exhausted; accepting to terminate".into(),
                            remaining: 0,
                        });
                        self.trace(
                            crate::infra::trace::tag::COMPLETION_VERDICT,
                            "completion allowed: denial budget exhausted".to_string(),
                            serde_json::json!({"allowed": true, "remaining": 0}),
                        );
                        return DriveOutcome::Finished(reason);
                    }
                    let available: Vec<String> = self
                        .env
                        .available_capabilities()
                        .into_iter()
                        .map(|s| s.to_string())
                        .collect();
                    let verdict = super::completeness::evaluate(
                        &self.assessment.family_progress,
                        &self.assessment.investigation,
                        &available,
                        70,
                    );
                    emit(Ev::CompletionEvaluated {
                        allowed: verdict.allowed,
                        reason: verdict.reason.clone(),
                        remaining: verdict.remaining.len(),
                    });
                    self.trace(
                        crate::infra::trace::tag::COMPLETION_VERDICT,
                        format!(
                            "completion {}: {} ({} remaining)",
                            if verdict.allowed { "allowed" } else { "rejected" },
                            verdict.reason,
                            verdict.remaining.len()
                        ),
                        serde_json::json!({
                            "allowed": verdict.allowed,
                            "reason": verdict.reason,
                            "remaining": verdict.remaining.iter().take(5).map(|r| serde_json::json!({
                                "family": r.family, "question": r.question,
                                "resolving_capability": r.resolving_capability,
                            })).collect::<Vec<_>>(),
                            "finish_denies": self.finish_denies,
                        }),
                    );
                    if verdict.allowed {
                        return DriveOutcome::Finished(reason);
                    }
                    let lines: Vec<String> = verdict
                        .remaining
                        .iter()
                        .take(5)
                        .map(|r| {
                            format!(
                                "[{}] {} (via {})",
                                r.family,
                                r.question,
                                r.resolving_capability.as_deref().unwrap_or("reasoning")
                            )
                        })
                        .collect();
                    self.cm.set_last_error(Some(format!(
                        "completion rejected ({}): high-value unresolved questions remain: {} — investigate the highest-value one next",
                        verdict.reason,
                        lines.join(" | ")
                    )));
                    self.finish_denies += 1;
                    self.step += 1;
                    self.persist_best_effort();
                    continue;
                }
                Decision::Reply { text } => {
                    // Autonomous runs have no user to answer: treat the
                    // reply as narration, count it as a step (so a
                    // reply-loop cannot spin forever) and keep driving.
                    self.trace(
                        crate::infra::trace::tag::DECISION_REPLY,
                        format!("reply ({} chars)", text.chars().count()),
                        serde_json::json!({"text_len": text.chars().count()}),
                    );
                    if autonomous {
                        self.step += 1;
                        continue;
                    }
                    return DriveOutcome::Replied(text);
                }
                Decision::Narrate { text } => {
                    // A verbal update that does NOT end the turn: tell
                    // the user what was found, then keep working. Costs a
                    // step so a narrate-loop cannot spin forever. The
                    // text lands in the context too — otherwise the model
                    // cannot tell what the user already knows and
                    // re-announces the same finding after every tool.
                    self.cm.add_narration(&text);
                    emit(Ev::Narrated { text: text.clone() });
                    self.trace(
                        crate::infra::trace::tag::DECISION_NARRATE,
                        format!("narrate ({} chars)", text.chars().count()),
                        serde_json::json!({"text_len": text.chars().count()}),
                    );
                    self.step += 1;
                }
                Decision::WebSearch { query, reason } => {
                    // Direct LLM tool (not a capability): the runtime
                    // executes the search itself and feeds the results
                    // back as observations. Reuses the tool-card events so
                    // UIs and session replay need no changes.
                    emit(Ev::CapabilityRequested {
                        capability: "web.search".into(),
                        target: query.clone(),
                        reason,
                        model_secs,
                    });
                    let t0 = std::time::Instant::now();
                    let results = super::web_search::search(
                        &query,
                        std::time::Duration::from_secs(20),
                    );
                    match results {
                        Ok(results) => {
                            let evidence = serde_json::json!({
                                "query": query,
                                "engine": "duckduckgo",
                                "result_count": results.len(),
                                "results": results.iter().map(|r| serde_json::json!({
                                    "title": r.title,
                                    "url": r.url,
                                    "snippet": r.snippet,
                                })).collect::<Vec<_>>(),
                            });
                            emit(Ev::ToolExecuted {
                                tool_id: "web-search".into(),
                                capability: "web.search".into(),
                                target: query.clone(),
                                exit_code: 0,
                                success: true,
                                timed_out: false,
                                output: serde_json::to_string(&evidence)
                                    .unwrap_or_default(),
                                tool_secs: t0.elapsed().as_secs_f64(),
                            });
                            let step = self.step;
                            if results.is_empty() {
                                let summary = format!(
                                    "web search for \"{query}\" returned no results"
                                );
                                self.cm.add_observation(
                                    &query, &summary, "web.search", step,
                                );
                                emit(Ev::ObservationAdded { summary });
                            } else {
                                for r in results.iter().take(8) {
                                    let mut summary =
                                        format!("web: {} — {}", r.title, r.url);
                                    if !r.snippet.is_empty() {
                                        let snip: String =
                                            r.snippet.chars().take(160).collect();
                                        summary.push_str(&format!(" · {snip}"));
                                    }
                                    self.cm.add_observation(
                                        &r.url, &summary, "web.search", step,
                                    );
                                    emit(Ev::ObservationAdded { summary });
                                }
                            }
                            self.trace(
                                crate::infra::trace::tag::DECISION_WEB_SEARCH,
                                format!("web search ok: {query} ({} hits)", results.len()),
                                serde_json::json!({
                                    "query_len": query.chars().count(),
                                    "result_count": results.len(),
                                    "tool_secs": t0.elapsed().as_secs_f64(),
                                }),
                            );
                        }
                        Err(e) => {
                            let msg = format!("web search failed: {e}");
                            emit(Ev::ToolExecuted {
                                tool_id: "web-search".into(),
                                capability: "web.search".into(),
                                target: query.clone(),
                                exit_code: 1,
                                success: false,
                                timed_out: false,
                                output: msg.clone(),
                                tool_secs: t0.elapsed().as_secs_f64(),
                            });
                            self.cm.set_last_error(Some(msg.clone()));
                            self.trace(
                                crate::infra::trace::tag::DECISION_WEB_SEARCH,
                                format!("web search failed: {query}"),
                                serde_json::json!({"query_len": query.chars().count(), "ok": false}),
                            );
                        }
                    }
                    self.step += 1;
                }
                Decision::CreateHypothesis {
                    statement,
                    confidence,
                } => {
                    // Event-only: the hypothesis is surfaced to the user
                    // (and persisted as a Think record). The model owns
                    // its reasoning; we do not rank or link it.
                    self.hypothesis_seq += 1;
                    // Also track it as a Hypothesis-stage finding so it
                    // survives restarts and can later be promoted with
                    // evidence (generic family inference, no app logic).
                    let family = super::families::infer_family(&statement, "").to_string();
                    let tracked = self.assessment.findings.create(
                        &statement,
                        &self.scope_label,
                        &family,
                        "Info",
                    );
                    emit(Ev::HypothesisAdded {
                        id: self.hypothesis_seq,
                        statement: statement.clone(),
                        confidence: confidence.clone(),
                    });
                    emit(Ev::HypothesisCreated {
                        statement: format!("tracked finding {tracked}"),
                        family: family.clone(),
                    });
                    self.trace(
                        crate::infra::trace::tag::HYPOTHESIS_CREATED,
                        format!("hypothesis H{} [{confidence}]", self.hypothesis_seq),
                        serde_json::json!({
                            "id": self.hypothesis_seq,
                            "confidence": confidence,
                            "family": family,
                            "tracked_finding": tracked,
                        }),
                    );
                    self.persist_best_effort();
                    self.step += 1;
                }
                Decision::FileRead {
                    path,
                    grep,
                    lines,
                    reason,
                } => {
                    self.run_file_read(
                        &path,
                        &grep,
                        &lines,
                        &reason,
                        model_secs,
                        &mut *emit,
                    );
                    self.step += 1;
                }
                Decision::FileWrite { path, content, reason } => {
                    // Vault references in file content resolve out of band
                    // too — a PoC that authenticates must not carry pasted
                    // secrets into history or traces.
                    match self.resolve_vault_refs_in_text(&content) {
                        Ok(resolved) => {
                            self.run_file_write(&path, &resolved, &reason, model_secs, &mut *emit)
                        }
                        Err(e) => {
                            self.cm.set_last_error(Some(e.clone()));
                            self.trace(
                                crate::infra::trace::tag::DECISION_FILE_WRITE,
                                format!("file write rejected (vault reference): {path}"),
                                serde_json::json!({"path": path, "ok": false}),
                            );
                        }
                    }
                    self.step += 1;
                }
                Decision::ReportFinding {
                    severity,
                    title,
                    target,
                    detail,
                } => {
                    // Model-reported registry entry: blank target means
                    // the assessment target in scope.
                    let tgt = if target.trim().is_empty() {
                        self.scope_label.clone()
                    } else {
                        target
                    };
                    let step = self.step;
                    let id =
                        self.cm
                            .add_finding(&severity, &title, &tgt, "model", &detail, step);
                    let status = self
                        .cm
                        .findings()
                        .iter()
                        .find(|f| f.id == id)
                        .map(|f| f.status.clone())
                        .unwrap_or_else(|| "open".into());
                    // Mirror into authoritative FindingStore (evidence-gated
                    // lifecycle): same title+target converges, latest
                    // evidence links, Hypothesis→Suspected when supported.
                    let family = super::families::infer_family(&title, &detail).to_string();
                    let tracked = self.assessment.findings.create(&title, &tgt, &family, &severity);
                    if let Some(ev) = self.assessment.evidence.records.last() {
                        if let Some(f) = self.assessment.findings.get_mut(tracked) {
                            f.add_evidence(ev.id);
                            let _ = f.transition(
                                super::findings::FindingStage::Suspected,
                                "model-reported with evidence on file",
                            );
                        }
                    }
                    let stage = self
                        .assessment
                        .findings
                        .get(tracked)
                        .map(|f| format!("{:?}", f.stage))
                        .unwrap_or_else(|| "Hypothesis".into());
                    // Weakness node keeps the graph honest about claimed
                    // impact without hardcoding any attack chain.
                    let wid = format!("weakness:finding-{tracked}");
                    self.assessment.attack_graph.upsert_node(
                        &wid,
                        super::attack_graph::NodeKind::Weakness,
                        &title,
                        step,
                    );
                    self.mark_family_evidence(&family);
                    emit(Ev::FindingRecorded {
                        id,
                        severity: severity.clone(),
                        title: title.clone(),
                        target: tgt.clone(),
                        status: status.clone(),
                        detail: detail.clone(),
                        step,
                    });
                    emit(Ev::FindingUpdated {
                        id: tracked,
                        stage: stage.clone(),
                        note: format!("family={family}"),
                    });
                    self.trace(
                        crate::infra::trace::tag::FINDING_REPORTED,
                        format!("finding F{id}/tracked-{tracked} [{severity}/{status}] {title}"),
                        serde_json::json!({
                            "registry_id": id,
                            "tracked_id": tracked,
                            "severity": severity,
                            "title": title,
                            "target": tgt,
                            "family": family,
                            "stage": stage,
                        }),
                    );
                    self.persist_best_effort();
                    self.step += 1;
                }
                Decision::UpdateFinding { id, status, note } => {
                    let step = self.step;
                    if self.cm.update_finding(id, &status, step) {
                        // Drive the authoritative lifecycle in lockstep:
                        // confirmed → promote as far as evidence allows,
                        // false_positive → Closed, anything else → note.
                        // Map by title+target (stores can diverge by id).
                        let norm = status.trim().to_lowercase();
                        let (cm_title, cm_target) = self
                            .cm
                            .findings()
                            .iter()
                            .find(|f| f.id == id)
                            .map(|f| (f.title.clone(), f.target.clone()))
                            .unwrap_or_default();
                        let tracked_id = self
                            .assessment
                            .findings
                            .findings
                            .iter()
                            .find(|f| f.title == cm_title && f.target == cm_target)
                            .map(|f| f.id)
                            .unwrap_or_else(|| id.min(self.assessment.findings.findings.len().max(1)));
                        let stage = if norm == "confirmed" {
                            self.assessment
                                .findings
                                .promote_toward_validated(tracked_id, &note);
                            self.assessment
                                .findings
                                .get(tracked_id)
                                .map(|f| format!("{:?}", f.stage))
                                .unwrap_or_else(|| "Suspected".into())
                        } else if norm == "false_positive" || norm == "false-positive" {
                            if let Some(f) = self.assessment.findings.get_mut(tracked_id) {
                                let _ = f.transition(
                                    super::findings::FindingStage::Closed,
                                    &note,
                                );
                            }
                            "Closed".to_string()
                        } else {
                            self.assessment
                                .findings
                                .get(tracked_id)
                                .map(|f| format!("{:?}", f.stage))
                                .unwrap_or_else(|| "Suspected".into())
                        };
                        let (severity, title, target, detail) = self
                            .cm
                            .findings()
                            .iter()
                            .find(|f| f.id == id)
                            .map(|f| {
                                (
                                    f.severity.clone(),
                                    f.title.clone(),
                                    f.target.clone(),
                                    if note.trim().is_empty() {
                                        f.detail.clone()
                                    } else {
                                        note.clone()
                                    },
                                )
                            })
                            .unwrap_or_default();
                        emit(Ev::FindingRecorded {
                            id,
                            severity,
                            title,
                            target,
                            status: status.clone(),
                            detail,
                            step,
                        });
                        emit(Ev::FindingUpdated {
                            id: tracked_id,
                            stage: stage.clone(),
                            note: note.clone(),
                        });
                        self.trace(
                            crate::infra::trace::tag::FINDING_UPDATED,
                            format!("finding F{id}/tracked-{tracked_id} -> {stage}"),
                            serde_json::json!({
                                "registry_id": id,
                                "tracked_id": tracked_id,
                                "status": status.clone(),
                                "stage": stage,
                            }),
                        );
                        self.persist_best_effort();
                    } else {
                        let known: Vec<String> = self
                            .cm
                            .findings()
                            .iter()
                            .map(|f| format!("F{}:{}", f.id, f.title))
                            .collect();
                        self.cm.set_last_error(Some(format!(
                            "no finding with id {id} (registry: {})",
                            if known.is_empty() {
                                "(empty — report findings with report_finding first)".to_string()
                            } else {
                                known.join(", ")
                            }
                        )));
                    }
                    self.step += 1;
                }
                Decision::VaultStore {
                    key,
                    value,
                    kind,
                    source,
                } => {
                    // Values never touch events/records/logs/traces — the
                    // event carries the key only (see VaultStored).
                    let step = self.step;
                    match self.vault_mut() {
                        Err(e) => self.cm.set_last_error(Some(e)),
                        Ok(v) => match v.store(&key, &value, &kind, &source, step) {
                            Ok(refreshed) => {
                                let keys = v.key_lines();
                                let kind = kind.trim().to_string();
                                let key = key.trim().to_string();
                                self.cm.set_vault_keys(keys);
                                emit(Ev::VaultStored {
                                    key: key.clone(),
                                    kind: kind.clone(),
                                    refreshed,
                                });
                                self.trace(
                                    crate::infra::trace::tag::VAULT_STORED,
                                    format!("vault stored {key} [{kind}]"),
                                    serde_json::json!({
                                        "key": key, "kind": kind, "refreshed": refreshed,
                                    }),
                                );
                            }
                            Err(e) => self.cm.set_last_error(Some(e)),
                        },
                    }
                    self.step += 1;
                }
                Decision::VaultRecall { query } => {
                    // Out-of-band values: the value is verified to exist
                    // but NEVER staged into context. The next step's tail
                    // confirms the key name and the `{{vault:key}}`
                    // reference syntax — the model writes references, the
                    // runtime injects values at execution time. Never into
                    // an event, record, trace, or prompt.
                    match self.vault_mut() {
                        Err(e) => self.cm.set_last_error(Some(e)),
                        Ok(v) => match v.recall(&query) {
                            Ok((key, _value)) => {
                                let key = key.to_string();
                                self.cm.stage_model_note(
                                    format!(
                                        "vault recalled `{key}` — reference it as {{{{vault:{key}}}}} in tool options or file content; values are injected at execution and never shown"
                                    ),
                                    self.step,
                                );
                                emit(Ev::VaultRecalled { key: key.clone() });
                                self.trace(
                                    crate::infra::trace::tag::VAULT_RECALLED,
                                    format!("vault recalled {key}"),
                                    serde_json::json!({"key": key}),
                                );
                            }
                            Err(e) => self.cm.set_last_error(Some(e)),
                        },
                    }
                    self.step += 1;
                }
                Decision::Execute {
                    capability,
                    target: action_target,
                    options,
                    reason,
                } => {
                    emit(Ev::CapabilityRequested {
                        capability: capability.clone(),
                        target: action_target.clone(),
                        reason: reason.clone(),
                        model_secs,
                    });
                    let mut request = CapabilityRequest {
                        capability,
                        target: action_target,
                        options,
                        reason,
                    };
                    // Legacy migration BEFORE validation: strictly
                    // well-formed `;`-separated header strings become
                    // structured maps per the capability schema. Ambiguous
                    // text stays a string and policy rejects it with an
                    // actionable error (never silently merged).
                    if let Some(def) = self.rt.caps.get(&request.capability) {
                        super::policy::normalize_request_options(&def, &mut request.options);
                    }
                    // Out-of-band vault values: `{{vault:key}}` references
                    // resolve HERE — after policy validated the reference
                    // form, before anything executes or traces. Values
                    // never enter prompts; traces carry sanitized_options
                    // plus the sink-side secret registry. Unknown keys
                    // fail like any argument error: feedback, no step.
                    match self.resolve_vault_refs_in_options(&request.options) {
                        Ok(opts) => request.options = opts,
                        Err(e) => {
                            emit(Ev::ActionRejected {
                                reason: e.clone(),
                            });
                            self.cm.set_last_error(Some(e.clone()));
                            self.trace(
                                crate::infra::trace::tag::HARNESS_FEEDBACK,
                                format!("vault reference failed: {e}"),
                                serde_json::json!({
                                    "capability": request.capability,
                                    "target": request.target,
                                }),
                            );
                            continue;
                        }
                    }
                    self.trace(
                        crate::infra::trace::tag::DECISION_EXECUTE,
                        format!("{} on {}", request.capability, request.target),
                        serde_json::json!({
                            "capability": request.capability,
                            "target": request.target,
                            "options": sanitized_options(&request.options),
                            "reason": request.reason,
                            "model_secs": model_secs,
                        }),
                    );
                    // Validation order is a security property: policy
                    // (capability exists → arguments valid → scope → risk)
                    // runs BEFORE provider selection, so no out-of-scope
                    // target can be executed regardless of provider.
                    match self.policy.validate(&request, self.rt.caps) {
                        Err(err) => {
                            let msg = err.to_string();
                            // High-risk requests become an approval REQUEST:
                            // the UI shows a dialog and the runtime blocks
                            // on the gate. Only a denial (or no gate /
                            // timeout) becomes rejection feedback. Emitting
                            // ActionRejected here made dialogs read
                            // "rejected: ..." before anything was rejected.
                            let needs_approval =
                                matches!(err, PolicyError::HighRiskRequiresApproval { .. })
                                    && !self.policy.allow_destructive.load(Ordering::SeqCst)
                                    && !self.approval_denied;
                            if needs_approval {
                                emit(Ev::ApprovalRequested {
                                    capability: request.capability.clone(),
                                    reason: msg,
                                });
                                self.trace(
                                    crate::infra::trace::tag::APPROVAL_REQUESTED,
                                    format!("approval requested for {}", request.capability),
                                    serde_json::json!({
                                        "capability": request.capability,
                                        "target": request.target,
                                    }),
                                );
                                match self.wait_for_approval() {
                                    ApprovalDecision::Allow => {
                                        self.approval_denied = false;
                                        // allow_destructive was latched with
                                        // the approval; the model's next
                                        // decision executes.
                                        self.trace(
                                            crate::infra::trace::tag::APPROVAL_DECIDED,
                                            format!("approval allowed for {}", request.capability),
                                            serde_json::json!({
                                                "capability": request.capability,
                                                "verdict": "allow",
                                            }),
                                        );
                                    }
                                    ApprovalDecision::Deny | ApprovalDecision::None => {
                                        // Deny (or no gate / timeout): the
                                        // model pivots. Don't block again.
                                        self.approval_denied = true;
                                        let feedback = format!(
                                            "high-risk capability `{}` requires approval that was not granted — pick a non-destructive capability, reply to the user, or finish",
                                            request.capability
                                        );
                                        emit(Ev::ActionRejected {
                                            reason: feedback.clone(),
                                        });
                                        self.cm.set_last_error(Some(feedback));
                                        self.trace(
                                            crate::infra::trace::tag::APPROVAL_DECIDED,
                                            format!("approval denied for {}", request.capability),
                                            serde_json::json!({
                                                "capability": request.capability,
                                                "verdict": "deny",
                                            }),
                                        );
                                    }
                                }
                            } else {
                                // Feed the rejection back; the model
                                // self-corrects next iteration without
                                // consuming a step. The event keeps the terse
                                // policy text (UI/tests); last_error carries
                                // the structured recovery version.
                                emit(Ev::ActionRejected {
                                    reason: msg.clone(),
                                });
                                let category =
                                    super::failure::FailureCategory::from_policy_error(&err);
                                let recovery = category.recovery(
                                    &request.capability,
                                    &request.target,
                                    &msg,
                                );
                                self.cm.set_last_error(Some(recovery.clone()));
                                self.trace(
                                    crate::infra::trace::tag::POLICY_REJECTED,
                                    format!(
                                        "policy rejected {} on {} [{}]",
                                        request.capability,
                                        request.target,
                                        category.name()
                                    ),
                                    serde_json::json!({
                                        "capability": request.capability,
                                        "target": request.target,
                                        "category": category.name(),
                                        "reason": msg,
                                    }),
                                );
                            }
                        }
                        Ok(()) => {
                            // Equivalent-request circuit breaker
                            // (runtime-owned, never prompt advice): the same
                            // request failing over and over means the request
                            // is wrong, not the target. Block before burning
                            // another execution + LLM round-trip. A retry is
                            // allowed when the arguments changed (different
                            // signature) or new evidence arrived since the
                            // failures (world changed — outcome might too).
                            const REPEAT_LIMIT: u32 = 3;
                            const BREAKER_TRIP_CAP: u32 = 2;
                            let sig = request_signature(&request);
                            if self.repeat_fail_count >= REPEAT_LIMIT
                                && self.repeat_fail_sig == sig
                                && self.repeat_fail_state == self.state_version()
                            {
                                self.breaker_trips += 1;
                                let remediation = format!(
                                    "BLOCKED: `{}` on `{}` failed or was ineffective {} times in a row with equivalent arguments (last: {}). Do NOT retry the identical request — change the request arguments, try a different capability/target, record a finding, or reply to the user.",
                                    request.capability,
                                    request.target,
                                    self.repeat_fail_count,
                                    self.repeat_fail_last
                                );
                                emit(Ev::ActionBlocked {
                                    reason: remediation.clone(),
                                });
                                self.cm.set_last_error(Some(remediation.clone()));
                                self.trace(
                                    crate::infra::trace::tag::BREAKER_BLOCKED,
                                    format!(
                                        "blocked {} on {} ({} fails, trip {})",
                                        request.capability,
                                        request.target,
                                        self.repeat_fail_count,
                                        self.breaker_trips
                                    ),
                                    serde_json::json!({
                                        "capability": request.capability,
                                        "target": request.target,
                                        "fail_count": self.repeat_fail_count,
                                        "trip": self.breaker_trips,
                                        "last_error_head": self.repeat_fail_last,
                                    }),
                                );
                                if self.breaker_trips >= BREAKER_TRIP_CAP {
                                    let stuck = format!(
                                        "I'm stuck: `{}` on `{}` keeps failing the same way and I kept retrying it instead of changing approach. {}",
                                        request.capability, request.target, remediation
                                    );
                                    self.trace(
                                        crate::infra::trace::tag::BREAKER_STUCK,
                                        format!(
                                            "stuck on {}|{}",
                                            request.capability, request.target
                                        ),
                                        serde_json::json!({
                                            "capability": request.capability,
                                            "target": request.target,
                                            "mode": if autonomous { "autonomous" } else { "interactive" },
                                        }),
                                    );
                                    if autonomous {
                                        return DriveOutcome::Finished(stuck);
                                    }
                                    return DriveOutcome::Replied(stuck);
                                }
                                continue;
                            }
                            match self.rt.providers.select(
                                &request.capability,
                                &request.options,
                                &self.env,
                            ) {
                                Err(err) => {
                                    let msg = err.to_string();
                                    emit(Ev::ActionRejected {
                                        reason: msg.clone(),
                                    });
                                    let category =
                                        super::failure::FailureCategory::from_provider_error(&err);
                                    let recovery = category.recovery(
                                        &request.capability,
                                        &request.target,
                                        &msg,
                                    );
                                    self.cm.set_last_error(Some(recovery));
                                    self.trace(
                                        crate::infra::trace::tag::PROVIDER_REJECTED,
                                        format!(
                                            "no provider for {} [{}]",
                                            request.capability,
                                            category.name()
                                        ),
                                        serde_json::json!({
                                            "capability": request.capability,
                                            "target": request.target,
                                            "category": category.name(),
                                            "reason": msg,
                                        }),
                                    );
                                }
                                Ok(provider) => {
                                    let provider_id = provider.id().to_string();
                                    emit(Ev::ProviderSelected {
                                        capability: request.capability.clone(),
                                        provider: provider_id.clone(),
                                    });
                                    self.trace(
                                        crate::infra::trace::tag::PROVIDER_SELECTED,
                                        format!(
                                            "{} -> {}",
                                            request.capability, provider_id
                                        ),
                                        serde_json::json!({
                                            "capability": request.capability,
                                            "target": request.target,
                                            "provider": provider_id,
                                            "options": sanitized_options(&request.options),
                                        }),
                                    );
                                    let ctx = ExecutionContext {
                                        executor: executor.as_ref(),
                                        env: &self.env,
                                    };
                                    // Automatic retries for fast failures:
                                    // transient blips recover without the
                                    // model burning a step. Timeouts are
                                    // never retried (the budget is spent),
                                    // and neither are deterministic
                                    // connection refusals (service down or
                                    // wrong port — retrying burns budget).
                                    // Tool-phase wall time: all attempts
                                    // plus inter-attempt backoff. Excludes
                                    // LLM time and approval waits.
                                    let exec_t0 = std::time::Instant::now();
                                    let mut attempt = 0usize;
                                    let result = loop {
                                        attempt += 1;
                                        emit(Ev::ToolStarted {
                                            capability: request.capability.clone(),
                                            provider: provider_id.clone(),
                                        });
                                        self.trace(
                                            crate::infra::trace::tag::TOOL_ATTEMPT,
                                            format!(
                                                "{} on {} via {} (attempt {attempt}/{MAX_ATTEMPTS})",
                                                request.capability, request.target, provider_id
                                            ),
                                            serde_json::json!({
                                                "capability": request.capability,
                                                "target": request.target,
                                                "provider": provider_id,
                                                "attempt": attempt,
                                            }),
                                        );
                                        // First attempt reports the exact
                                        // invocation (TOOL.ARGV / TOOL.HTTP_CALL
                                        // from the provider); retries reuse it.
                                        let result = if attempt == 1 {
                                            let mut emit_trace =
                                                |tag: &str, msg: String, data: serde_json::Value| {
                                                    self.trace(tag, msg, data)
                                                };
                                            provider.execute_traced(
                                                &request,
                                                &ctx,
                                                &mut emit_trace,
                                            )
                                        } else {
                                            provider.execute(&request, &ctx)
                                        };
                                        emit(Ev::ToolFinished {
                                            capability: request.capability.clone(),
                                            provider: provider_id.clone(),
                                        });
                                        if result.success()
                                            || result.timed_out
                                            || result.is_non_retryable()
                                            || attempt >= MAX_ATTEMPTS
                                        {
                                            break result;
                                        }
                                        // Cancellation-aware pause between attempts.
                                        for _ in 0..10 {
                                            if self.rt.handle.is_cancelled() {
                                                break;
                                            }
                                            std::thread::sleep(std::time::Duration::from_millis(
                                                100,
                                            ));
                                        }
                                        if self.rt.handle.is_cancelled() {
                                            break result;
                                        }
                                    };
                                    let mut output_note = String::new();
                                    if !result.success() {
                                        // Failure reason must be visible: errors that
                                        // never reach stdout/stderr (provider guards,
                                        // internal providers) otherwise show as a bare
                                        // "failed (exit -1)" card with no explanation.
                                        if let Some(err) = &result.error {
                                            output_note
                                                .push_str(&format!("\n[medusa] error: {err}"));
                                        }
                                        if attempt > 1 {
                                            output_note.push_str(&format!(
                                                "\n[medusa] failed after {attempt} attempts"
                                            ));
                                        }
                                    }
                                    // Empty SUCCESS needs an explanation, or the
                                    // model (and user) can't tell a filter from
                                    // a dead target: annotate the card output
                                    // and record an observation the model sees.
                                    let empty_success = result.success()
                                        && result.combined_output().trim().is_empty();
                                    let option_list = request
                                        .options
                                        .iter()
                                        .map(|(k, v)| format!("{k}={v}"))
                                        .collect::<Vec<_>>()
                                        .join(", ");
                                    if empty_success {
                                        output_note = if !option_list.is_empty() {
                                            format!(
                                                "\n[medusa] completed successfully with no output — the applied filters ({option_list}) may have excluded all results; consider re-running without filters"
                                            )
                                        } else {
                                            format!(
                                                "\n[medusa] completed successfully with no output — the target may be unreachable or returned nothing"
                                            )
                                        };
                                    }
                                    emit(Ev::ToolExecuted {
                                        tool_id: result.tool_id.clone(),
                                        capability: result.capability.clone(),
                                        target: result.target.clone(),
                                        exit_code: result.exit_code,
                                        success: result.success(),
                                        timed_out: result.timed_out,
                                        output: format!(
                                            "{}{}",
                                            truncate_evidence(&result.combined_output()),
                                            output_note
                                        ),
                                        tool_secs: exec_t0.elapsed().as_secs_f64(),
                                    });
                                    self.trace(
                                        crate::infra::trace::tag::TOOL_RESULT,
                                        format!(
                                            "{} on {} exit={} {} ({} attempts, {:.1}s)",
                                            result.tool_id,
                                            result.target,
                                            result.exit_code,
                                            if result.timed_out {
                                                "timed out"
                                            } else if result.success() {
                                                "ok"
                                            } else {
                                                "failed"
                                            },
                                            attempt,
                                            exec_t0.elapsed().as_secs_f64(),
                                        ),
                                        serde_json::json!({
                                            "tool_id": result.tool_id,
                                            "capability": result.capability,
                                            "target": result.target,
                                            "provider": provider_id,
                                            "exit_code": result.exit_code,
                                            "success": result.success(),
                                            "timed_out": result.timed_out,
                                            "attempts": attempt,
                                            "stdout_len": result.stdout.len(),
                                            "stderr_len": result.stderr.len(),
                                            "non_retryable": result.is_non_retryable(),
                                        }),
                                    );
                                    // Raw evidence for the model: the
                                    // undistilled output rides the context
                                    // alongside the parsed observations.
                                    self.cm.add_evidence(
                                        &result.tool_id,
                                        &result.target,
                                        &result.combined_output(),
                                    );
                                    // Authoritative evidence log (write
                                    // everything; the LLM reads selectively
                                    // via the ContextManager projection).
                                    let evid = self.assessment.evidence.push(
                                        &result.capability,
                                        &provider_id,
                                        &result.tool_id,
                                        &result.target,
                                        &option_list,
                                        &result.combined_output(),
                                        result.timed_out,
                                        result.success(),
                                        self.step,
                                    );
                                    self.trace(
                                        crate::infra::trace::tag::STATE_EVIDENCE,
                                        format!(
                                            "evidence #{evid}: {} via {} (success={})",
                                            result.tool_id,
                                            provider_id,
                                            result.success()
                                        ),
                                        serde_json::json!({
                                            "evidence_id": evid,
                                            "tool_id": result.tool_id,
                                            "capability": result.capability,
                                            "target": result.target,
                                            "provider": provider_id,
                                            "success": result.success(),
                                        }),
                                    );
                                    // Distill raw output into normalized
                                    // observations and feed BOTH stores — the
                                    // context manager for budgeted model
                                    // visibility, the world model for the
                                    // asset graph.
                                    if result.error.is_none() && !result.timed_out {
                                        let parsed = super::parsers::parse_tool_output(
                                            &result.tool_id,
                                            &result.combined_output(),
                                            &request.target,
                                        );
                                        let raw_len = result.combined_output().len();
                                        if parsed.is_empty() && raw_len > 0 {
                                            // Parse miss: raw output is preserved
                                            // as evidence but no parser understood
                                            // it. Say so explicitly (with a Parse
                                            // recovery note) instead of leaving
                                            // the model guessing — unless a more
                                            // specific error is already set.
                                            if self.cm.last_error().is_none() {
                                                let cat = super::failure::FailureCategory::Parse;
                                                self.cm.set_last_error(Some(cat.recovery(
                                                    &request.capability,
                                                    &request.target,
                                                    &format!(
                                                        "tool={}, raw={} chars, parsed=0 observations (raw kept as evidence)",
                                                        result.tool_id, raw_len
                                                    ),
                                                )));
                                            }
                                        }
                                        self.trace(
                                            crate::infra::trace::tag::PARSER_RESULT,
                                            format!(
                                                "parser {}: {} raw chars -> {} observations{}",
                                                result.tool_id,
                                                raw_len,
                                                parsed.len(),
                                                if parsed.is_empty() && raw_len > 0 {
                                                    " (PARSE MISS)"
                                                } else {
                                                    ""
                                                }
                                            ),
                                            serde_json::json!({
                                                "tool_id": result.tool_id,
                                                "raw_len": raw_len,
                                                "parsed_n": parsed.len(),
                                                "parse_miss": parsed.is_empty() && raw_len > 0,
                                                "summaries": parsed.iter().map(|p| &p.summary).collect::<Vec<_>>(),
                                            }),
                                        );
                                        for p in &parsed {
                                            let step = self.step;
                                            self.cm.add_observation(
                                                &p.target, &p.summary, &p.source, step,
                                            );
                                            // Authoritative state update (generic):
                                            // evidence log + entity merge + graph.
                                            if let Some(detail) = &p.detail {
                                                let kind = format!("{:?}", detail.kind());
                                                let new_edges =
                                                    self.assessment.apply_detail(detail, step);
                                                self.trace(
                                                    crate::infra::trace::tag::STATE_ENTITY,
                                                    format!("entity {kind}: {}", p.summary.chars().take(120).collect::<String>()),
                                                    serde_json::json!({
                                                        "kind": kind,
                                                        "summary": p.summary,
                                                        "source": p.source,
                                                    }),
                                                );
                                                for (from, to, kind) in &new_edges {
                                                    self.trace(
                                                        crate::infra::trace::tag::STATE_GRAPH_EDGE,
                                                        format!("{from} -> {to} [{kind}]"),
                                                        serde_json::json!({
                                                            "from": from, "to": to, "kind": kind,
                                                        }),
                                                    );
                                                }
                                                // Scanner-confirmed weakness classes
                                                // count as family evidence without
                                                // auto-confirming a finding.
                                                if let crate::model::observation::ObservationDetail::VulnerabilityFound { name, .. } = detail {
                                                    let fam = super::families::infer_family(name, &p.summary);
                                                    self.mark_family_evidence(fam);
                                                }
                                            }
                                            self.assessment.touch(
                                                super::assessment::now_unix(),
                                                step,
                                            );
                                            emit(Ev::ObservationAdded {
                                                summary: p.summary.clone(),
                                            });
                                        }
                                        {
                                            let n = self.assessment.attack_graph.nodes.len();
                                            let e = self.assessment.attack_graph.edges.len();
                                            if n > 0 {
                                                emit(Ev::AttackGraphUpdated {
                                                    nodes: n,
                                                    edges: e,
                                                    newly_reachable: self
                                                        .assessment
                                                        .attack_graph
                                                        .newly_reachable(
                                                            self.assessment
                                                                .last_completed_step
                                                                .saturating_sub(1),
                                                        )
                                                        .iter()
                                                        .take(5)
                                                        .map(|x| x.label.clone())
                                                        .collect(),
                                                });
                                            }
                                        }
                                        // The empty-success explanation as a
                                        // first-class observation: the model
                                        // sees WHY there is nothing instead of
                                        // guessing (and re-probing).
                                        if empty_success {
                                            let summary = if !option_list.is_empty() {
                                                format!(
                                                    "{} on {} completed with zero findings — filters ({}) excluded all results, output was empty (not a failure)",
                                                    result.tool_id, result.target, option_list
                                                )
                                            } else {
                                                format!(
                                                    "{} on {} completed with no output — the target may be unreachable or returns nothing (not a failure)",
                                                    result.tool_id, result.target
                                                )
                                            };
                                            let step = self.step;
                                            self.cm.add_observation(
                                                &result.target,
                                                &summary,
                                                &result.tool_id,
                                                step,
                                            );
                                            emit(Ev::ObservationAdded { summary });
                                        }
                                    }
                                    // Feed execution failures back so the model
                                    // can self-correct on the next step. The
                                    // feedback is structured: capability,
                                    // category, sanitized facts, labeled
                                    // suspicion, next diagnostic step.
                                    if !result.success() {
                                        let category =
                                            super::failure::FailureCategory::from_tool_result(
                                                &result,
                                            );
                                        let facts = format!(
                                            "tool={}, exit={}, timed_out={}, {}",
                                            result.tool_id,
                                            result.exit_code,
                                            result.timed_out,
                                            result.error.clone().unwrap_or_else(|| {
                                                format!("exit code {}", result.exit_code)
                                            })
                                        );
                                        let recovery = category.recovery(
                                            &request.capability,
                                            &request.target,
                                            &facts,
                                        );
                                        self.cm.set_last_error(Some(recovery.clone()));
                                        self.trace(
                                            crate::infra::trace::tag::HARNESS_FEEDBACK,
                                            format!(
                                                "feedback [{}] to model",
                                                category.name()
                                            ),
                                            serde_json::json!({
                                                "capability": request.capability,
                                                "target": request.target,
                                                "category": category.name(),
                                            }),
                                        );
                                    }
                                    // Honest completion: an exit-0 run can
                                    // still have tested nothing (sqlmap
                                    // "[CRITICAL] no parameter(s) found",
                                    // trivy "FATAL" on a URL target). Such
                                    // runs are recorded as INEFFECTIVE so
                                    // the planner keeps the unknown open
                                    // instead of declaring victory.
                                    let mut effective = result.success();
                                    if effective {
                                        if let Some(note) = execution_ineffective_note(&result) {
                                            effective = false;
                                            let summary = format!(
                                                "{} on {} ran but tested nothing — {}",
                                                result.tool_id, result.target, note
                                            );
                                            let step = self.step;
                                            self.cm.add_observation(
                                                &result.target,
                                                &summary,
                                                &result.tool_id,
                                                step,
                                            );
                                            self.cm.set_last_error(Some(summary.clone()));
                                            emit(Ev::ObservationAdded { summary: summary.clone() });
                                            self.trace(
                                                crate::infra::trace::tag::TOOL_INEFFECTIVE,
                                                format!(
                                                    "{} on {} ineffective",
                                                    result.tool_id, result.target
                                                ),
                                                serde_json::json!({
                                                    "tool_id": result.tool_id,
                                                    "target": result.target,
                                                    "note": note,
                                                }),
                                            );
                                        }
                                    }
                                    let step = self.step;
                                    self.cm.add_action(
                                        step,
                                        request.capability.clone(),
                                        provider_id,
                                        request.target.clone(),
                                        request.reason.clone(),
                                        effective,
                                    );
                                    // Repeat-failure breaker bookkeeping
                                    // (decision-level: one outcome per
                                    // Execute, not per retry attempt).
                                    let err_head = if !result.success() {
                                        result
                                            .error
                                            .as_deref()
                                            .unwrap_or("")
                                            .lines()
                                            .next()
                                            .unwrap_or("")
                                            .to_string()
                                    } else if !effective {
                                        format!("{} ran but tested nothing (exit 0, ineffective)", result.tool_id)
                                    } else {
                                        String::new()
                                    };
                                    let was_success = result.success();
                                    self.note_execution_outcome(
                                        &request,
                                        effective,
                                        &err_head,
                                    );
                                    if !effective {
                                        self.trace(
                                            crate::infra::trace::tag::HARNESS_FEEDBACK,
                                            format!(
                                                "feedback to model: {} on {} {} (streak {})",
                                                result.tool_id,
                                                result.target,
                                                if was_success { "ineffective" } else { "failed" },
                                                self.repeat_fail_count
                                            ),
                                            serde_json::json!({
                                                "tool_id": result.tool_id,
                                                "target": result.target,
                                                "repeat_sig": self.repeat_fail_sig,
                                                "repeat_count": self.repeat_fail_count,
                                            }),
                                        );
                                    } else {
                                        // A capability that just succeeded may
                                        // unblock objectives waiting on it.
                                        let reopened = self
                                            .assessment
                                            .investigation
                                            .reopen_blocked(&request.capability);
                                        if !reopened.is_empty() {
                                            self.trace(
                                                crate::infra::trace::tag::STATE_REOPENED,
                                                format!(
                                                    "{} reopened {:?}",
                                                    request.capability, reopened
                                                ),
                                                serde_json::json!({
                                                    "capability": request.capability,
                                                    "objective_ids": reopened,
                                                }),
                                            );
                                        }
                                    }
                                    self.tool_results.push(result);
                                    self.step += 1;
                                    self.persist_best_effort();
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Consume the session into the headless result shape (CLI/tests).
    fn into_result(mut self, target: Target, finish_reason: FinishReason) -> InvestigationResult {
        // Final snapshot so close/reopen restores the finished state.
        self.persist_best_effort();
        let model_error = match &finish_reason {
            FinishReason::TooManyModelErrors { last_error, .. } => Some(last_error.clone()),
            _ => None,
        };
        InvestigationResult {
            target,
            steps_taken: self.step,
            planned_actions: self
                .cm
                .actions()
                .iter()
                .map(|a| PlannedAction {
                    step: a.step,
                    capability: a.capability.clone(),
                    provider: a.provider.clone(),
                    target: a.target.clone(),
                    reason: a.reason.clone(),
                })
                .collect(),
            tool_results: std::mem::take(&mut self.tool_results),
            finish_reason,
            model_error,
        }
    }
}

/// Extract host-like tokens from free user text. Deliberately
/// conservative: only URLs, dotted domains with a plausible last label,
/// and IPv4 literals. WE control this — the model never grants scope.
fn hosts_in(message: &str) -> Vec<String> {
    let mut out = Vec::new();
    for tok in message.split_whitespace() {
        let tok = tok
            .trim_matches(|c: char| c.is_ascii_punctuation() && c != '.' && c != ':' && c != '-');
        let tok = tok.trim_matches(|c: char| c.is_ascii_punctuation());
        if tok.is_empty() {
            continue;
        }
        // URL: strip to host.
        if tok.starts_with("http://") || tok.starts_with("https://") {
            let host = super::policy::host_of(tok);
            if is_grantable_host(&host) && !out.contains(&host) {
                out.push(host);
            }
            continue;
        }
        // Strip an explicit :port before host matching — "localhost:3000",
        // "127.0.0.1:8080", "example.com:8080" are host mentions too.
        // (Port must be all digits so "12:30" times and "::1" literals
        // are left alone.)
        let bare = match tok.split_once(':') {
            Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => h,
            _ => tok,
        };
        // IPv4 literal.
        if is_ipv4(bare) && !out.contains(&bare.to_string()) {
            out.push(bare.to_string());
            continue;
        }
        // localhost — dotless but an explicit, unambiguous host.
        if bare.eq_ignore_ascii_case("localhost") && !out.contains(&"localhost".to_string()) {
            out.push("localhost".to_string());
            continue;
        }
        // Dotted domain: labels of alnum/hyphen, last label ≥ 2 alpha.
        if is_plausible_host(bare) && bare.contains('.') && !out.contains(&bare.to_string()) {
            out.push(bare.to_string());
        }
    }
    out
}

/// Hosts that may be granted scope from a user mention. `localhost` is
/// dotless and IPv4 literals fail the domain-shape check, so both are
/// accepted explicitly — "http://127.0.0.1:3000/" is a host mention.
fn is_grantable_host(s: &str) -> bool {
    is_plausible_host(s) || is_ipv4(s) || s.eq_ignore_ascii_case("localhost")
}

fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 3
                && p.chars().all(|c| c.is_ascii_digit())
                && p.parse::<u16>().map(|n| n <= 255).unwrap_or(false)
        })
}

fn is_plausible_host(s: &str) -> bool {
    if s.len() > 253 || !s.contains('.') {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    labels.iter().all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    }) && labels
        .last()
        .is_some_and(|l| l.len() >= 2 && l.chars().all(|c| c.is_ascii_alphabetic()))
}

/// Cap raw evidence carried in `ToolExecuted` events. UIs show the head of
/// the output; full output stays in the `ToolResult` for parsing.
fn truncate_evidence(raw: &str) -> String {
    const CAP: usize = 12_000;
    if raw.len() <= CAP {
        raw.to_string()
    } else {
        // Cut on a char boundary to avoid slicing mid-UTF-8.
        let mut end = CAP;
        while end > 0 && !raw.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}\n… [truncated {} bytes]", &raw[..end], raw.len() - end)
    }
}

/// Marker sniffing for exit-0 runs that did no useful work. sqlmap exits
/// 0 while printing "[CRITICAL] no parameter(s) found"; trivy prints
/// "FATAL" (stderr) and exits non-zero (already a failure). Only called
/// for nominally successful runs.
fn execution_ineffective_note(result: &super::executor::ToolResult) -> Option<&'static str> {
    if result.combined_output().contains("[CRITICAL]") {
        return Some(
            "the tool reported a CRITICAL condition, e.g. sqlmap without testable parameters — re-run against the full endpoint URL with `data` for parameters",
        );
    }
    if result.stderr.contains("FATAL") {
        return Some("the tool hit a FATAL error — this invocation cannot apply to the target (e.g. a filesystem scanner pointed at a URL)");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::model::StubProvider;
    use crate::agent::model::{OptionSet, OptionValue};
    use crate::model::ToolStatus;
    use std::collections::HashMap;

    fn harness(installed: &[&str]) -> (ToolRegistry, CapabilityRegistry, EnvironmentState) {
        let tools = ToolRegistry::builtin();
        let caps = CapabilityRegistry::builtin();
        let mut state = EnvironmentState::empty();
        state.tools = tools
            .all()
            .iter()
            .map(|t| {
                let up = installed.contains(&t.id.as_str());
                (
                    t.id.clone(),
                    ToolStatus {
                        tool_id: t.id.clone(),
                        installed: up,
                        executable_path: up.then(|| format!("/bin/{}", t.id)),
                        version: up.then(|| "1.0".into()),
                        platform: "linux".into(),
                        arch: "x64".into(),
                        healthy: up,
                        adapter_available: false,
                        capabilities: if up { t.capabilities.clone() } else { vec![] },
                        missing_dependencies: vec![],
                        diagnostic: String::new(),
                    },
                )
            })
            .collect::<HashMap<_, _>>();
        // Capability snapshots must exist for available/unavailable queries.
        let tools_by_id = tools
            .all()
            .iter()
            .map(|t| (t.id.clone(), t.clone()))
            .collect::<HashMap<_, _>>();
        state.capabilities =
            crate::core::discovery::derive_capabilities(&state.tools, &tools_by_id, &caps);
        (tools, caps, state)
    }

    #[test]
    fn loop_resolves_execute_hypothesis_finish() {
        let (tools, caps, state) = harness(&["nmap"]);
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::Execute {
                capability: "network.port_scan".into(),
                target: "10.0.0.1".into(),
                options: OptionSet::new(),
                reason: "open ports unknown".into(),
            },
            Decision::CreateHypothesis {
                statement: "SSH may be exposed".into(),
                confidence: "low".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let res = rt.investigate(Target::new("10.0.0.1"));
        assert!(matches!(res.finish_reason, FinishReason::ModelFinished(_)));
        assert_eq!(res.steps_taken, 2);
        assert_eq!(res.planned_actions.len(), 1);
        assert_eq!(res.planned_actions[0].provider, "nmap");
    }

    #[test]
    fn file_write_then_file_read_roundtrips_confined() {
        let (tools, caps, state) = harness(&[]);
        // Point the work root at a temp dir so the test never touches the
        // real medusa state dir.
        let workroot = std::env::temp_dir().join(format!(
            "medusa-file-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&workroot).unwrap();
        std::env::set_var("MEDUSA_WORK_ROOT", &workroot);
        // Stub: write, then read the same file, then reply.
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::FileWrite {
                path: "poc.txt".into(),
                content: "FORGED-JWT".into(),
                reason: "write a proof".into(),
            },
            Decision::FileRead {
                path: "poc.txt".into(),
                grep: Some("FORGED".into()),
                lines: None,
                reason: "verify the write".into(),
            },
            Decision::Reply {
                text: "done".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let res = rt.investigate(Target::new("127.0.0.1"));
        // Confined path: %TEMP%/.../work/127.0.0.1/poc.txt — NOT in the cwd.
        let confined = workroot.join("127.0.0.1").join("poc.txt");
        assert_eq!(
            std::fs::read_to_string(&confined).unwrap(),
            "FORGED-JWT"
        );
        // Reaching this far means the read happened (Stub drives on).
        assert!(matches!(res.finish_reason, FinishReason::ModelFinished(_)));
        // Cleanup.
        let _ = std::fs::remove_dir_all(&workroot);
        std::env::remove_var("MEDUSA_WORK_ROOT");
    }

    #[test]
    fn policy_rejection_is_fed_back_without_consuming_steps() {
        let (tools, caps, state) = harness(&[]); // nothing installed
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![Decision::Execute {
            capability: "network.port_scan".into(),
            target: "10.0.0.1".into(),
            options: OptionSet::new(),
            reason: "try anyway".into(),
        }]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let res = rt.investigate(Target::new("10.0.0.1"));
        // Rejected (no provider), stub exhausts, finishes. No steps consumed.
        assert_eq!(res.planned_actions.len(), 0);
        assert_eq!(res.steps_taken, 0);
    }

    /// Fails the first N decides with Transport, then serves the script.
    /// Records the rendered wire messages of every call.
    struct FlakyProvider {
        failures_left: std::sync::Mutex<usize>,
        failure_text: String,
        script: std::sync::Mutex<Vec<Decision>>,
        seen: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl ModelProvider for FlakyProvider {
        fn name(&self) -> &str {
            "flaky"
        }
        fn decide(&self, ctx: &ContextView) -> Result<Decision, ModelError> {
            let rendered = serde_json::to_string(
                &crate::agent::model::render_chat_messages(
                    &ctx.brief,
                    &ctx.transcript,
                    &ctx.tail,
                ),
            )
            .unwrap();
            self.seen.lock().unwrap().push(rendered);
            let mut left = self.failures_left.lock().unwrap();
            if *left > 0 {
                *left -= 1;
                return Err(ModelError::Transport(self.failure_text.clone()));
            }
            Ok(self.script.lock().unwrap().remove(0))
        }
        fn chat(&self, _system: &str, _user: &str) -> Result<String, ModelError> {
            Ok("chat".into())
        }
    }

    #[test]
    fn model_retry_rebuilds_byte_identical_request() {
        use std::sync::{Arc, Mutex};
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (tools, caps, state) = harness(&[]);
        let model: Box<dyn ModelProvider> = Box::new(FlakyProvider {
            failures_left: Mutex::new(1),
            failure_text: "boom: connection reset by peer".into(),
            script: Mutex::new(vec![
                Decision::Narrate {
                    text: "working on it".into(),
                },
                Decision::Reply {
                    text: "done".into(),
                },
            ]),
            seen: Arc::clone(&seen),
        });
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let mut sess = rt.session();
        let outcome = sess.run_turn("go", &mut |_| {});
        assert!(matches!(outcome, DriveOutcome::Replied(_)));
        let seen = seen.lock().unwrap();
        // fail, same-step retry, next step: 3 calls.
        assert_eq!(seen.len(), 3);
        // The retry is byte-identical: no error amendment leaks into the
        // rebuilt request (the staged note stays hidden on the same step).
        assert_eq!(seen[0], seen[1]);
        // The failure surfaces in the NEXT step's tail instead.
        assert!(
            seen[2].contains("MODEL NOTE"),
            "third call should carry the staged note: {}",
            seen[2]
        );
        assert!(seen[2].contains("connection reset by peer"));
    }

    #[test]
    fn slow_burn_failures_give_up_early() {
        use std::sync::{Arc, Mutex};
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (tools, caps, state) = harness(&[]);
        // Always stalls: two burned budgets must end the turn, not five.
        let model: Box<dyn ModelProvider> = Box::new(FlakyProvider {
            failures_left: Mutex::new(99),
            failure_text: "stream stalled: no data for 300s".into(),
            script: Mutex::new(vec![]),
            seen: Arc::clone(&seen),
        });
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let mut sess = rt.session();
        let outcome = sess.run_turn("go", &mut |_| {});
        match outcome {
            DriveOutcome::TooManyModelErrors { count, .. } => assert_eq!(count, 2),
            other => panic!("expected early give-up, got {other:?}"),
        }
        assert_eq!(seen.lock().unwrap().len(), 2);
    }

    #[test]
    fn cancelled_model_error_ends_turn_without_retries() {
        use std::sync::{Arc, Mutex};
        // Stop pressed mid-call: the provider surfaces ModelError::
        // Cancelled; the drive loop must end the turn as Cancelled —
        // no error count, no retry, no user-facing failure.
        struct CancelProvider {
            calls: Arc<Mutex<usize>>,
        }
        impl ModelProvider for CancelProvider {
            fn name(&self) -> &str {
                "cancel"
            }
            fn decide(&self, _ctx: &ContextView) -> Result<Decision, ModelError> {
                *self.calls.lock().unwrap() += 1;
                Err(ModelError::Cancelled)
            }
            fn chat(&self, _system: &str, _user: &str) -> Result<String, ModelError> {
                unreachable!("chat is not part of this path")
            }
        }
        let calls = Arc::new(Mutex::new(0usize));
        let (tools, caps, state) = harness(&[]);
        let model: Box<dyn ModelProvider> = Box::new(CancelProvider {
            calls: Arc::clone(&calls),
        });
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let mut sess = rt.session();
        let outcome = sess.run_turn("go", &mut |_| {});
        assert!(matches!(outcome, DriveOutcome::Cancelled), "got {outcome:?}");
        // Exactly one call: Cancelled must not be retried.
        assert_eq!(*calls.lock().unwrap(), 1);
    }

    #[test]
    fn retry_after_header_is_honored_and_capped() {        use std::sync::{Arc, Mutex};
        let (tools, caps, state) = harness(&[]);
        let model: Box<dyn ModelProvider> = Box::new(FlakyProvider {
            failures_left: Mutex::new(1),
            failure_text: "https://gw/v1: status code 429: busy [retry_after=1s]".into(),
            script: Mutex::new(vec![Decision::Reply {
                text: "recovered".into(),
            }]),
            seen: Arc::new(Mutex::new(Vec::new())),
        });
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let mut sess = rt.session();
        // ~1s honored wait, then recovery — not the 100ms fast path and
        // not an unbounded stall.
        let t0 = std::time::Instant::now();
        let outcome = sess.run_turn("go", &mut |_| {});
        assert!(matches!(outcome, DriveOutcome::Replied(_)));
        assert!(t0.elapsed() >= std::time::Duration::from_millis(900));
    }

    #[test]
    fn session_reply_ends_turn_and_persists_conversation() {
        let (tools, caps, state) = harness(&["nmap"]);
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![Decision::Reply {
            text: "Ready when you are.".into(),
        }]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let mut sess = rt.session();
        let mut seen: Vec<AgentEvent> = Vec::new();
        let out = sess.run_turn("hello there", &mut |ev| seen.push(ev));
        assert!(matches!(out, DriveOutcome::Replied(t) if t == "Ready when you are."));
        assert!(seen.iter().any(|e| matches!(
            e,
            AgentEvent::Reply { text } if text == "Ready when you are."
        )));
        // The user message is in the conversation even though no scope was
        // granted (no host-like token in "hello there").
        assert!(seen
            .iter()
            .all(|e| !matches!(e, AgentEvent::ScopeGranted { .. })));
    }

    #[test]
    fn session_grants_scope_only_from_user_mentions() {
        let (tools, caps, state) = harness(&["nmap"]);
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            // First tries a target the user NEVER mentioned → rejected.
            Decision::Execute {
                capability: "network.port_scan".into(),
                target: "evil.example.net".into(),
                options: OptionSet::new(),
                reason: "not mentioned".into(),
            },
            // Then the mentioned one → executes.
            Decision::Execute {
                capability: "network.port_scan".into(),
                target: "scanme.example.com".into(),
                options: OptionSet::new(),
                reason: "user asked".into(),
            },
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let mut sess = rt.session();
        let mut seen: Vec<AgentEvent> = Vec::new();
        let out = sess.run_turn("please assess scanme.example.com when you can", &mut |ev| {
            seen.push(ev)
        });
        assert!(matches!(out, DriveOutcome::Finished(_)));
        // Scope granted exactly for the mentioned host.
        assert!(seen.iter().any(|e| matches!(
            e,
            AgentEvent::ScopeGranted { target } if target == "scanme.example.com"
        )));
        // The unmentioned target was rejected by policy before execution.
        assert!(seen
            .iter()
            .any(|e| matches!(e, AgentEvent::ActionRejected { reason } if reason.contains("outside assessment scope"))));
        // And the mentioned one actually ran (stub executor not wired, so
        // provider executes via LocalProcessExecutor on /bin/nmap — which
        // does not exist; what matters here is that it was NOT scope-
        // rejected: no second rejection event).
        assert_eq!(
            seen.iter()
                .filter(|e| matches!(e, AgentEvent::ActionRejected { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn autonomous_mode_treats_reply_as_step_and_continues() {
        let (tools, caps, state) = harness(&[]);
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::Reply {
                text: "narration".into(),
            },
            Decision::Finish {
                reason: "wrapped up".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let res = rt.investigate(Target::new("10.0.0.1"));
        // The reply did not terminate the autonomous run.
        assert!(matches!(res.finish_reason, FinishReason::ModelFinished(r) if r == "wrapped up"));
        assert_eq!(res.steps_taken, 1);
    }

    #[test]
    fn max_steps_bounds_the_loop() {
        let (tools, caps, state) = harness(&["nmap"]);
        // Infinite script of hypotheses; runtime must stop anyway.
        struct Infinite;
        impl ModelProvider for Infinite {
            fn name(&self) -> &str {
                "infinite"
            }
            fn decide(&self, _ctx: &ContextView) -> Result<Decision, ModelError> {
                Ok(Decision::CreateHypothesis {
                    statement: "more".into(),
                    confidence: "low".into(),
                })
            }
            fn chat(&self, _system: &str, _user: &str) -> Result<String, ModelError> {
                Ok("more".to_string())
            }
        }
        let rt = AgentRuntime::new(Box::new(Infinite), &tools, &caps, &state).with_max_steps(5);
        let res = rt.investigate(Target::new("10.0.0.1"));
        assert!(matches!(res.finish_reason, FinishReason::MaxSteps(5)));
        assert_eq!(res.steps_taken, 5);
    }

    #[test]
    fn interactive_turn_after_max_steps_continues_from_the_same_session() {
        // The actor model keeps ONE AgentSession across messages. The first
        // turn burns the per-turn budget (MaxSteps) but must NOT reset
        // step/context: a "continue" turn drives forward from step 25 with
        // a fresh budget of 25 more, so an investigation split across
        // turns is genuinely resumed rather than restarted.
        let (tools, caps, state) = harness(&["nmap"]);
        struct Infinite;
        impl ModelProvider for Infinite {
            fn name(&self) -> &str {
                "infinite"
            }
            fn decide(&self, _ctx: &ContextView) -> Result<Decision, ModelError> {
                Ok(Decision::CreateHypothesis {
                    statement: "more".into(),
                    confidence: "low".into(),
                })
            }
            fn chat(&self, _system: &str, _user: &str) -> Result<String, ModelError> {
                Ok("more".to_string())
            }
        }
        let rt = AgentRuntime::new(Box::new(Infinite), &tools, &caps, &state).with_max_steps(5);
        let mut sess = rt.session();
        // First turn: hits the 5-step budget on-turn.
        let out1 = sess.run_turn("assess scanme.example.com", &mut |_| {});
        assert!(matches!(out1, DriveOutcome::MaxSteps(5)));

        // A "continue" turn must advance budget (turn_start_step)
        // WITHOUT resetting the environment/scope. With an infinite script
        // it reaches a second MaxSteps — proof it ran MORE steps, i.e. it
        // really continued.
        let out2 = sess.run_turn("continue", &mut |_| {});
        assert!(
            matches!(out2, DriveOutcome::MaxSteps(5)),
            "second turn must run another budget of steps, got {out2:?}"
        );
        assert_eq!(sess.step, 10, "continue must not reset the step counter");
        // Scope survived across turns.
        assert!(sess
            .policy
            .scope_roots()
            .contains(&"scanme.example.com".to_string()));
    }

    #[test]
    fn mid_turn_message_is_folded_into_the_running_turn_without_stopping() {
        // A message arrives mid-turn. It must NOT end the turn: instead it
        // joins the conversation (so the model sees it next decision) and
        // grants scope from any host it names — all within the same turn.
        let (tools, caps, state) = harness(&["nmap"]);
        // The model narrates once, then finishes — so the turn ends on the
        // model's own terms, never because of the injected message.
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::Narrate { text: "working".into() },
            Decision::Finish { reason: "done".into() },
        ]));
        // Deliver exactly one mid-turn message, on the first drain only.
        let pending = std::sync::Arc::new(std::sync::Mutex::new(vec![
            "also check newtarget.example.com".to_string(),
        ]));
        let drain_src = std::sync::Arc::clone(&pending);
        let rt = AgentRuntime::new(model, &tools, &caps, &state)
            .with_input_drain(move || std::mem::take(&mut *drain_src.lock().unwrap()));
        let mut sess = rt.session();
        let mut seen: Vec<AgentEvent> = Vec::new();
        let out = sess.run_turn("assess scanme.example.com", &mut |ev| seen.push(ev));
        // The turn ended because the MODEL finished, not because of input.
        assert!(matches!(out, DriveOutcome::Finished(_)), "got {out:?}");
        // The injected message was folded in and surfaced as an event.
        assert!(seen.iter().any(|e| matches!(
            e,
            AgentEvent::UserMessageSeen { text } if text == "also check newtarget.example.com"
        )));
        // Its host was granted scope mid-turn.
        assert!(seen.iter().any(|e| matches!(
            e,
            AgentEvent::ScopeGranted { target } if target == "newtarget.example.com"
        )));
        assert!(sess
            .policy
            .scope_roots()
            .contains(&"newtarget.example.com".to_string()));
        // And it reached the model-facing conversation.
        assert!(sess
            .cm
            .conversation()
            .iter()
            .any(|t| t.user == "also check newtarget.example.com"));
    }

    #[test]
    fn pending_model_switch_is_applied_before_the_next_llm_call() {
        // The operator switches providers mid-turn. The drive loop must swap
        // the model at the next step boundary — BEFORE the next decision —
        // so the new provider is the one that makes the call, not the old
        // one that may be slow/broken (the grid-kimi-vs-opencode case).
        let (tools, caps, state) = harness(&["nmap"]);
        // A distinctly-named provider that just finishes, so we can assert
        // which model actually ran the step.
        struct Named(&'static str);
        impl ModelProvider for Named {
            fn name(&self) -> &str {
                self.0
            }
            fn decide(&self, _ctx: &ContextView) -> Result<Decision, ModelError> {
                Ok(Decision::Finish { reason: "done".into() })
            }
            fn chat(&self, _s: &str, _u: &str) -> Result<String, ModelError> {
                Ok("x".to_string())
            }
        }
        // Reload hands back the NEW provider exactly once (the switch), then
        // `None` forever after — mirroring a one-shot `swap_pending` flag.
        let fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let fired_src = std::sync::Arc::clone(&fired);
        let rt = AgentRuntime::new(Box::new(Named("old-provider")), &tools, &caps, &state)
            .with_model_reload(move || {
                if !fired_src.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    let m: Box<dyn ModelProvider> = Box::new(Named("new-provider"));
                    Some(m)
                } else {
                    None
                }
            });
        assert_eq!(rt.model_name(), "old-provider");
        let mut sess = rt.session();
        let mut seen: Vec<AgentEvent> = Vec::new();
        let _ = sess.run_turn("assess scanme.example.com", &mut |ev| seen.push(ev));
        // The swap landed: the active model is now the new provider.
        assert_eq!(
            sess.rt.model_name(),
            "new-provider",
            "mid-turn switch must rebind the model before the next LLM call"
        );
        // And the switch surfaced to the UI as a status line.
        assert!(
            seen.iter().any(|e| matches!(
                e,
                AgentEvent::Status { message } if message.contains("new-provider")
            )),
            "a model switch should emit a Status note"
        );
    }

    #[test]
    fn cancellation_stops_mid_investigation() {
        let (tools, caps, state) = harness(&["nmap"]);
        struct Infinite;
        impl ModelProvider for Infinite {
            fn name(&self) -> &str {
                "infinite"
            }
            fn decide(&self, _ctx: &ContextView) -> Result<Decision, ModelError> {
                Ok(Decision::CreateHypothesis {
                    statement: "more".into(),
                    confidence: "low".into(),
                })
            }
            fn chat(&self, _system: &str, _user: &str) -> Result<String, ModelError> {
                Ok("more".to_string())
            }
        }
        let rt = AgentRuntime::new(Box::new(Infinite), &tools, &caps, &state);
        rt.handle().cancel(); // cancel before starting
        let res = rt.investigate(Target::new("10.0.0.1"));
        assert!(matches!(res.finish_reason, FinishReason::Cancelled));
        assert_eq!(res.steps_taken, 0);
    }

    #[test]
    fn stop_applies_to_the_turn_in_flight_only() {
        use crate::agent::events::AgentEvent;
        use std::cell::RefCell;
        // Regression: one Stop latched the shared handle forever, so
        // every later turn insta-cancelled at the top of the drive loop
        // (session looks alive — messages recorded — but never acts).
        // The provider below cancels mid-turn, exactly like a user
        // pressing Stop while the agent works.
        struct CancelMidTurn {
            handle: RuntimeHandle,
            first: std::sync::atomic::AtomicBool,
        }
        impl ModelProvider for CancelMidTurn {
            fn name(&self) -> &str {
                "cancel-mid-turn"
            }
            fn decide(&self, _ctx: &ContextView) -> Result<Decision, ModelError> {
                if self
                    .first
                    .swap(false, std::sync::atomic::Ordering::SeqCst)
                {
                    self.handle.cancel();
                    Ok(Decision::Narrate {
                        text: "working".into(),
                    })
                } else {
                    Ok(Decision::Reply {
                        text: "alive".into(),
                    })
                }
            }
            fn chat(&self, _system: &str, _user: &str) -> Result<String, ModelError> {
                Ok("chat".into())
            }
        }
        let (tools, caps, state) = harness(&[]);
        let handle = RuntimeHandle::default();
        let model: Box<dyn ModelProvider> = Box::new(CancelMidTurn {
            handle: handle.clone(),
            first: std::sync::atomic::AtomicBool::new(true),
        });
        let rt = AgentRuntime::new(model, &tools, &caps, &state).with_handle(handle);
        let mut sess = rt.session();
        let seen = RefCell::new(Vec::new());
        let outcome = sess.run_turn("go", &mut |ev| {
            seen.borrow_mut().push(ev);
        });
        // The turn did real work (a narration) before the Stop landed.
        assert!(seen.borrow().iter().any(|e| matches!(
            e,
            AgentEvent::Narrated { .. }
        )));
        assert!(
            matches!(outcome, DriveOutcome::Cancelled),
            "mid-turn Stop still aborts the turn, got: {outcome:?}"
        );
        // The next turn starts fresh: the latch does not leak across
        // the turn boundary.
        let outcome = sess.run_turn("are you there?", &mut |_| {});
        assert!(
            matches!(outcome, DriveOutcome::Replied(_)),
            "got: {outcome:?}"
        );
    }

    /// Fails the first `fails` executions of `exe`, then succeeds.
    struct FlakyExecutor {
        exe: &'static str,
        fails: std::sync::atomic::AtomicUsize,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl FlakyExecutor {
        fn new(exe: &'static str, fails: usize) -> Self {
            Self {
                exe,
                fails: std::sync::atomic::AtomicUsize::new(fails),
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn total_calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl ProcessExecutor for FlakyExecutor {
        fn run(
            &self,
            exe: &str,
            _args: &[String],
            _timeout: std::time::Duration,
        ) -> crate::agent::executor::ProcessOutput {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if exe.contains(self.exe)
                && self
                    .fails
                    .fetch_update(
                        std::sync::atomic::Ordering::SeqCst,
                        std::sync::atomic::Ordering::SeqCst,
                        |n| if n == 0 { None } else { Some(n - 1) },
                    )
                    .is_ok()
            {
                crate::agent::executor::ProcessOutput {
                    exit_code: 1,
                    stdout: String::new(),
                    stderr: "transient blip".into(),
                    timed_out: false,
                    error: None,
                }
            } else {
                crate::agent::executor::ProcessOutput {
                    exit_code: 0,
                    stdout: "port 80 open".into(),
                    stderr: String::new(),
                    timed_out: false,
                    error: None,
                }
            }
        }
    }

    #[test]
    fn transient_failure_is_retried_automatically() {
        let (tools, caps, state) = harness(&["nmap"]);
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::Execute {
                capability: "network.port_scan".into(),
                target: "10.0.0.1".into(),
                options: OptionSet::new(),
                reason: "one decision".into(),
            },
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let flaky = Arc::new(FlakyExecutor::new("nmap", 1));
        let rt = rt.with_executor(flaky.clone());
        let res = rt.investigate(Target::new("10.0.0.1"));
        // One decision, two executions (1 fail + 1 success), step consumed,
        // action recorded, no disable.
        assert!(matches!(res.finish_reason, FinishReason::ModelFinished(_)));
        assert_eq!(flaky.total_calls(), 2);
        assert_eq!(res.steps_taken, 1);
        assert_eq!(res.planned_actions.len(), 1);
    }

    #[test]
    fn narrate_updates_user_without_ending_the_turn() {
        let (tools, caps, state) = harness(&["httpx"]);
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::Execute {
                capability: "http.probe".into(),
                target: "10.0.0.1".into(),
                options: OptionSet::new(),
                reason: "probe".into(),
            },
            Decision::Narrate {
                text: "Found exposed admin configuration endpoint.".into(),
            },
            Decision::Execute {
                capability: "http.probe".into(),
                target: "10.0.0.1".into(),
                options: OptionSet::new(),
                reason: "keep going".into(),
            },
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state).with_executor(Arc::new(
            crate::agent::executor::StubExecutor::success("httpx", "up"),
        ));
        let mut sess = rt.session();
        let mut seen: Vec<AgentEvent> = Vec::new();
        sess.run_turn("assess 10.0.0.1", &mut |ev| seen.push(ev));
        // The narration reached the user as an event...
        assert!(seen.iter().any(|e| matches!(
            e,
            AgentEvent::Narrated { text } if text.starts_with("Found exposed admin")
        )));
        // ...AND the model's own context: the next decision sees what was
        // already reported, so it cannot re-announce the same finding.
        let view = rt.context_view(&sess.env, &Target::new("10.0.0.1"), sess.step, &sess.cm);
        assert!(view
            .narrations
            .iter()
            .any(|n| n.starts_with("Found exposed admin")));
        // The turn did NOT end at the narration: both executes ran.
        assert_eq!(sess.cm.actions().len(), 2);
    }

    #[test]
    fn high_risk_approval_gate_allows_after_user_consent() {
        use crate::agent::executor::StubExecutor;
        // web.vulnerability_scan is gated by the Destructive
        // web.rce_chain_validation test: without approval it is rejected.
        let (tools, caps, state) = harness(&["nuclei"]);
        let exec = || Decision::Execute {
            capability: "web.vulnerability_scan".into(),
            target: "10.0.0.1".into(),
            options: OptionSet::new(),
            reason: "scan it".into(),
        };
        // First Execute is rejected (dialog), second is the model's retry.
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            exec(),
            exec(),
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state).with_executor(Arc::new(
            StubExecutor::success("nuclei", "{\"findings\":[]}"),
        ));
        // The user's dialog answer, already waiting when the runtime blocks.
        let gate = Arc::new(std::sync::Mutex::new(Some(true)));
        let rt = rt.with_approval_gate(gate);
        let mut seen: Vec<AgentEvent> = Vec::new();
        let res = rt.investigate_with(Target::new("10.0.0.1"), &mut |ev| seen.push(ev));
        // The high-risk block is an approval REQUEST (dialog), not a
        // rejection; the gate's approval latched the flag and the retry
        // executed.
        assert_eq!(
            seen.iter()
                .filter(|e| matches!(e, AgentEvent::ApprovalRequested { .. }))
                .count(),
            1
        );
        assert_eq!(
            seen.iter()
                .filter(|e| matches!(e, AgentEvent::ActionRejected { .. }))
                .count(),
            0
        );
        assert_eq!(res.planned_actions.len(), 1);
        assert_eq!(res.planned_actions[0].provider, "nuclei");
    }

    #[test]
    fn high_risk_denial_does_not_block_the_loop() {
        use crate::agent::executor::StubExecutor;
        let (tools, caps, state) = harness(&["nuclei"]);
        let exec = || Decision::Execute {
            capability: "web.vulnerability_scan".into(),
            target: "10.0.0.1".into(),
            options: OptionSet::new(),
            reason: "try again".into(),
        };
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            exec(),
            exec(),
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state)
            .with_executor(Arc::new(StubExecutor::success("nuclei", "{}")));
        // User denied: the first rejection consumes the denial, the second
        // must NOT block again (no gate decision pending) — the run
        // terminates instead of deadlocking.
        let gate = Arc::new(std::sync::Mutex::new(Some(false)));
        let rt = rt.with_approval_gate(gate);
        let mut seen: Vec<AgentEvent> = Vec::new();
        let res = rt.investigate_with(Target::new("10.0.0.1"), &mut |ev| seen.push(ev));
        assert!(matches!(res.finish_reason, FinishReason::ModelFinished(_)));
        // One approval request (dialog trigger), then the denial feedback
        // and the un-gated second attempt's rejection.
        assert_eq!(
            seen.iter()
                .filter(|e| matches!(e, AgentEvent::ApprovalRequested { .. }))
                .count(),
            1
        );
        assert_eq!(
            seen.iter()
                .filter(|e| matches!(e, AgentEvent::ActionRejected { .. }))
                .count(),
            2
        );
        assert_eq!(res.planned_actions.len(), 0);
    }

    #[test]
    fn empty_success_with_filters_explains_itself() {
        use crate::agent::executor::StubExecutor;
        use crate::agent::model::{OptionSet, OptionValue};
        let (tools, caps, state) = harness(&["nuclei"]);
        let mut options = OptionSet::new();
        options.insert("severity".into(), OptionValue::Str("high".into()));
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::Execute {
                capability: "web.vulnerability_scan".into(),
                target: "10.0.0.1".into(),
                options,
                reason: "filtered scan".into(),
            },
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state)
            .with_executor(Arc::new(StubExecutor::success("nuclei", "")))
            // web.vulnerability_scan is high-risk gated: pre-approve so this
            // test exercises the empty-output path, not the approval gate.
            .with_approval_flag(Arc::new(AtomicBool::new(true)));
        let mut seen: Vec<AgentEvent> = Vec::new();
        let res = rt.investigate_with(Target::new("10.0.0.1"), &mut |ev| seen.push(ev));
        // Executed fine, but with empty output and a filter applied...
        assert_eq!(res.planned_actions.len(), 1);
        let executed = seen.iter().find_map(|e| match e {
            AgentEvent::ToolExecuted { output, .. } => Some(output.clone()),
            _ => None,
        });
        // ...the card output explains the filter (not "no output" silence)...
        assert!(executed
            .as_deref()
            .is_some_and(|o| o.contains("filters (severity=high) may have excluded all results")));
        // ...and the model's context gets an observation saying the same.
        assert!(seen.iter().any(|e| matches!(
            e,
            AgentEvent::ObservationAdded { summary }
                if summary.contains("filters (severity=high) excluded all results")
        )));
    }

    #[test]
    fn argv_guarded_tools_are_not_advertised_as_available() {
        // ghidra is "installed and healthy" in the env, but its argv is
        // empty on purpose (headless needs a two-step workflow), so every
        // provider of binary.analysis is structurally unusable — the
        // capability must not be advertised. zap, by contrast, now has a
        // real headless argv (-cmd -quickurl) and IS advertised.
        let (tools, caps, state) = harness(&["ghidra", "zap", "nuclei"]);
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let sess = rt.session();
        let target = Target::new("example.com");
        let view = rt.context_view(&sess.env, &target, sess.step, &sess.cm);
        assert!(!view
            .available_capabilities
            .contains(&"binary.analysis".to_string()));
        assert!(!view
            .capability_schemas
            .iter()
            .any(|s| s.starts_with("binary.analysis")));
        assert!(view
            .available_capabilities
            .contains(&"web.dynamic_testing".to_string()));
        // nuclei still covers vulnerability_scan.
        assert!(view
            .available_capabilities
            .contains(&"web.vulnerability_scan".to_string()));
    }

    #[test]
    fn localhost_and_host_port_mentions_grant_scope() {
        // localhost in all three shapes is a host mention.
        assert_eq!(hosts_in("assess localhost"), vec!["localhost".to_string()]);
        assert_eq!(
            hosts_in("probe localhost:3000"),
            vec!["localhost".to_string()]
        );
        assert_eq!(
            hosts_in("scan http://localhost:3000/"),
            vec!["localhost".to_string()]
        );
        // host:port for IPs and domains too (port must not leak into the
        // granted root).
        assert_eq!(
            hosts_in("hit 127.0.0.1:8080"),
            vec!["127.0.0.1".to_string()]
        );
        assert_eq!(
            hosts_in("test example.com:8080"),
            vec!["example.com".to_string()]
        );
        // URL-wrapped IPv4 is a host mention as well.
        assert_eq!(
            hosts_in("assess http://127.0.0.1:3000/"),
            vec!["127.0.0.1".to_string()]
        );
        // Ordinary words and time-like tokens still grant nothing.
        assert!(hosts_in("run this tool again now").is_empty());
        assert!(hosts_in("meet at 12:30 sharp").is_empty());
    }

    #[test]
    fn loopback_forms_are_interchangeable_in_scope() {
        use crate::agent::policy::ScopePolicy;
        // The user mentions one loopback form; the model targets another.
        let mut scope = ScopePolicy::empty();
        assert!(scope.grant("localhost"));
        assert!(scope.is_in_scope("http://127.0.0.1:3000/"));
        assert!(scope.is_in_scope("http://[::1]:3000/"));
        assert!(!scope.is_in_scope("http://example.com/"));
        // And the reverse direction.
        let mut scope = ScopePolicy::empty();
        assert!(scope.grant("127.0.0.1"));
        assert!(scope.is_in_scope("localhost:3000"));
        assert!(!scope.is_in_scope("example.com"));
    }

    #[test]
    fn rehydrate_restores_scope_conversation_and_observations() {
        use crate::infra::sessions::{SessionRecord, TimedRecord};
        let (tools, caps, state) = harness(&["nuclei"]);
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let mut sess = rt.session();
        let records = vec![
            TimedRecord {
                time: 1,
                record: SessionRecord::Target {
                    target: "owasp.org".into(),
                },
            },
            TimedRecord {
                time: 2,
                record: SessionRecord::Chat {
                    user: "assess owasp.org".into(),
                    agent: "starting recon".into(),
                    user_time: 0,
                },
            },
            TimedRecord {
                time: 3,
                record: SessionRecord::Obs {
                    text: "nuclei on owasp.org completed with zero findings".into(),
                },
            },
        ];
        sess.rehydrate(&records);
        // Scope root and label restored - the model can target it again.
        assert!(sess.policy.scope_roots().contains(&"owasp.org".to_string()));
        assert_eq!(sess.scope_label, "owasp.org");
        // Conversation and observations are visible in the next view.
        let target = Target::new(&sess.scope_label);
        let view = rt.context_view(&sess.env, &target, sess.step, &sess.cm);
        assert_eq!(view.conversation.len(), 1);
        assert_eq!(view.conversation[0].user, "assess owasp.org");
        assert!(view
            .observations
            .iter()
            .any(|o| o.contains("zero findings")));
        // Idempotent: replaying the same file changes nothing.
        sess.rehydrate(&records);
        assert_eq!(sess.policy.scope_roots().len(), 1);
        let view = rt.context_view(&sess.env, &target, sess.step, &sess.cm);
        assert_eq!(view.conversation.len(), 1);
    }

    #[test]
    fn full_resume_restores_what_rehydrate_alone_cannot() {
        // rehydrate() replays the session LOG, which has no record kind
        // for prior_actions or raw evidence at all — only the full
        // (assessment + ContextManager) snapshot resume can bring those
        // back. This proves the snapshot round-trip through the exact
        // runtime entry points a reopen would use.
        let (tools, caps, state) = harness(&["nmap"]);
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);

        let mut sess = rt.session_with_id("resume-test-a1");
        sess.policy.grant_scope("10.0.0.1");
        sess.scope_label = "10.0.0.1".into();
        sess.step = 7;
        sess.cm.add_action(
            7,
            "network.port_scan".into(),
            "nmap".into(),
            "10.0.0.1".into(),
            "map services".into(),
            true,
        );
        sess.cm.add_evidence("nmap", "10.0.0.1", "22/tcp open ssh");
        sess.cm.set_last_error(Some("connection refused on :8080".into()));
        sess.cm.set_last_error(None);
        sess.assessment.last_completed_step = 7;
        sess.persist_best_effort();

        // Simulate a process restart: load both snapshots fresh from disk
        // and resume through the production entry point, exactly as a
        // reopen would.
        let loaded_assessment = super::super::assessment::load(&sess.assessment.id).unwrap();
        let loaded_cm = super::super::context::load(&sess.assessment.id).unwrap();
        let resumed = rt.resume_session_with_context(loaded_assessment, loaded_cm);

        assert_eq!(resumed.step, 7, "step must not reset to 0 on resume");
        // The regression this guards against: scope lives only in
        // ExecutionPolicy (never itself serialized) and used to be
        // restored solely by `rehydrate()`'s Rec::Target handling, which
        // the full snapshot resume path does not call. Without syncing
        // scope_label/target_roots onto AssessmentState, every action
        // after a reopen rejected with "outside assessment scope ('')"
        // even though the exact same target worked moments earlier.
        assert_eq!(resumed.scope_label, "10.0.0.1", "scope label must survive resume");
        assert!(
            resumed.policy.scope_roots().contains(&"10.0.0.1".to_string()),
            "granted scope roots must survive resume, got {:?}",
            resumed.policy.scope_roots()
        );
        let request = CapabilityRequest {
            capability: "network.port_scan".into(),
            target: "10.0.0.1".into(),
            options: OptionSet::new(),
            reason: "re-scan after resume".into(),
        };
        assert!(
            resumed.policy.validate(&request, &caps).is_ok(),
            "a resumed session must be able to act on its own previously-granted target"
        );
        let target = Target::new("10.0.0.1");
        let view = rt.context_view(&resumed.env, &target, resumed.step, &resumed.cm);
        assert_eq!(view.prior_actions.len(), 1);
        assert!(view.prior_actions[0].contains("map services"));
        assert_eq!(view.recent_evidence.len(), 1);
        assert_eq!(
            view.recent_errors,
            vec!["connection refused on :8080".to_string()]
        );

        // Clean up the snapshot files this test wrote under the real
        // assessments dir.
        let dir = super::super::assessment::assessments_dir();
        let _ = std::fs::remove_file(dir.join("resume-test-a1.json"));
        let _ = std::fs::remove_file(dir.join("resume-test-a1.context.json"));
    }

    #[test]
    fn tool_is_never_disabled_across_repeated_failures() {
        // Tools are never removed from the model. Repeated failure feeds
        // the model (last_error + the observations), and a later attempt
        // against a now-healthy target still executes — the model's full
        // hindsight (prior_actions) prevents the retry loop, not a breaker.
        let (tools, caps, state) = harness(&["nmap"]);
        // Fail the first 3 executions (1 decision x 3 retries), then let
        // the 4th decision succeed.
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::Execute {
                capability: "network.port_scan".into(),
                target: "10.0.0.1".into(),
                options: OptionSet::new(),
                reason: "attempt 1 - fails 3x".into(),
            },
            Decision::Execute {
                capability: "network.port_scan".into(),
                target: "10.0.0.1".into(),
                options: OptionSet::new(),
                reason: "attempt 2 - now succeeds".into(),
            },
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let flaky = Arc::new(FlakyExecutor::new("nmap", 3));
        let rt = rt.with_executor(flaky.clone());
        let mut sess = rt.session();
        let mut seen: Vec<AgentEvent> = Vec::new();
        sess.run_turn("assess 10.0.0.1", &mut |ev| seen.push(ev));
        // The second decision executed the tool successfully — nothing
        // disabled it for the first decision's failures.
        assert!(seen.iter().any(|e| matches!(
            e,
            AgentEvent::ToolExecuted { tool_id, success, .. } if tool_id == "nmap" && *success
        )));
        // No "disabled" notices of any kind were emitted.
        assert!(!seen
            .iter()
            .any(|e| matches!(e, AgentEvent::Error { message } if message.contains("disabled") || message.contains("disabled for"))));
    }

    #[test]
    fn repeat_failure_breaker_blocks_identical_retries_then_ends_turn() {
        // The same capability+target failing decision after decision means
        // the request shape is wrong, not the target. After 3 consecutive
        // failures the 4th identical decision is blocked without executing;
        // a model that retries past the block ends the turn with a stuck
        // explanation instead of burning calls forever.
        let (tools, caps, state) = harness(&["nmap"]);
        let script: Vec<Decision> = (0..6)
            .map(|i| Decision::Execute {
                capability: "network.port_scan".into(),
                target: "10.0.0.1".into(),
                options: OptionSet::new(),
                reason: format!("attempt {i}"),
            })
            .collect();
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(script));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let flaky = Arc::new(FlakyExecutor::new("nmap", 100));
        let rt = rt.with_executor(flaky.clone());
        let mut sess = rt.session();
        let mut seen: Vec<AgentEvent> = Vec::new();
        let outcome = sess.run_turn("assess 10.0.0.1", &mut |ev| seen.push(ev));
        // Exactly 3 executions happened (one per decision); the 4th
        // identical decision was blocked, the 5th ended the turn.
        let executed = seen
            .iter()
            .filter(|e| matches!(e, AgentEvent::ToolExecuted { .. }))
            .count();
        assert_eq!(executed, 3, "breaker must stop executions at 3, got {executed}");
        assert!(
            seen.iter().any(|e| matches!(
                e,
                AgentEvent::ActionBlocked { reason } if reason.contains("BLOCKED")
            )),
            "breaker must emit ActionBlocked"
        );
        assert!(
            matches!(&outcome, DriveOutcome::Replied(text) if text.contains("stuck")),
            "turn must end with a stuck explanation, got: {outcome:?}"
        );
    }

    #[test]
    fn breaker_allows_retry_when_arguments_change() {
        // Same capability+target with DIFFERENT options is a different
        // request: after 3 identical failures, a changed-argument retry
        // must execute instead of tripping the breaker.
        let (tools, caps, state) = harness(&["nmap"]);
        let mut script: Vec<Decision> = (0..3)
            .map(|i| Decision::Execute {
                capability: "network.port_scan".into(),
                target: "10.0.0.1".into(),
                options: OptionSet::new(),
                reason: format!("attempt {i}"),
            })
            .collect();
        let mut changed = OptionSet::new();
        changed.insert("ports".into(), OptionValue::Str("80,443".into()));
        script.push(Decision::Execute {
            capability: "network.port_scan".into(),
            target: "10.0.0.1".into(),
            options: changed,
            reason: "same target, narrowed ports".into(),
        });
        script.push(Decision::Finish {
            reason: "done".into(),
        });
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(script));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let flaky = Arc::new(FlakyExecutor::new("nmap", 100));
        let rt = rt.with_executor(flaky.clone());
        let mut sess = rt.session();
        let mut seen: Vec<AgentEvent> = Vec::new();
        let _ = sess.run_turn("assess 10.0.0.1", &mut |ev| seen.push(ev));
        let executed = seen
            .iter()
            .filter(|e| matches!(e, AgentEvent::ToolExecuted { .. }))
            .count();
        assert_eq!(executed, 4, "changed-argument retry must execute, got {executed}");
        assert!(
            !seen.iter().any(|e| matches!(
                e,
                AgentEvent::ActionBlocked { .. }
            )),
            "breaker must not trip on changed arguments"
        );
    }

    #[test]
    fn breaker_rearms_after_new_evidence() {
        // Three identical failures, then the world changes (a file write
        // lands a new observation), then the identical request retries:
        // the retry is allowed once because state advanced since the
        // failures. A repeat after that re-trips the streak.
        let (tools, caps, state) = harness(&["nmap"]);
        let workroot = std::env::temp_dir().join(format!(
            "medusa-breaker-test-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&workroot);
        std::env::set_var("MEDUSA_WORK_ROOT", &workroot);
        let script: Vec<Decision> = vec![
            Decision::Execute {
                capability: "network.port_scan".into(),
                target: "10.0.0.1".into(),
                options: OptionSet::new(),
                reason: "attempt 1".into(),
            },
            Decision::Execute {
                capability: "network.port_scan".into(),
                target: "10.0.0.1".into(),
                options: OptionSet::new(),
                reason: "attempt 2".into(),
            },
            Decision::Execute {
                capability: "network.port_scan".into(),
                target: "10.0.0.1".into(),
                options: OptionSet::new(),
                reason: "attempt 3".into(),
            },
            Decision::FileWrite {
                path: "note.txt".into(),
                content: "state change".into(),
                reason: "record progress".into(),
            },
            Decision::Execute {
                capability: "network.port_scan".into(),
                target: "10.0.0.1".into(),
                options: OptionSet::new(),
                reason: "retry after new evidence".into(),
            },
            Decision::Finish {
                reason: "done".into(),
            },
        ];
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(script));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let flaky = Arc::new(FlakyExecutor::new("nmap", 100));
        let rt = rt.with_executor(flaky.clone());
        let mut sess = rt.session();
        let mut seen: Vec<AgentEvent> = Vec::new();
        let _ = sess.run_turn("assess 10.0.0.1", &mut |ev| seen.push(ev));
        let nmap_runs = seen
            .iter()
            .filter(|e| {
                matches!(e, AgentEvent::ToolExecuted { tool_id, .. } if tool_id == "nmap")
            })
            .count();
        assert_eq!(
            nmap_runs, 4,
            "re-armed retry must execute after state changed, got {nmap_runs}"
        );
        assert!(
            !seen.iter().any(|e| matches!(
                e,
                AgentEvent::ActionBlocked { .. }
            )),
            "breaker must not trip when state advanced: {:?}",
            seen.iter()
                .filter_map(|e| match e {
                    AgentEvent::ActionBlocked { reason } => Some(reason.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>()
        );
        let _ = std::fs::remove_dir_all(&workroot);
    }

    #[test]
    fn trace_captures_full_loop_sequence_in_order() {
        use std::sync::{Arc, Mutex};
        // Golden sequence: every stage of one failing Execute decision
        // must appear in the trace in loop order, all tags CAPITAL.
        let (tools, caps, state) = harness(&[]);
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![Decision::Execute {
            capability: "http.request".into(),
            target: "http://127.0.0.1:9/".into(),
            options: OptionSet::new(),
            reason: "probe".into(),
        }]));
        let log: Arc<Mutex<Vec<crate::infra::trace::TraceEntry>>> =
            Arc::new(Mutex::new(Vec::new()));
        let log2 = Arc::clone(&log);
        let rt =
            AgentRuntime::new(model, &tools, &caps, &state).with_tracer(move |e| {
                log2.lock().unwrap().push(e)
            });
        let _ = rt.investigate(Target::new("127.0.0.1"));
        let tags: Vec<String> = log
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.tag.clone())
            .collect();
        // Tags are CAPITAL LETTERS only.
        for t in &tags {
            assert!(
                t.chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '.' || c == '_'),
                "tag not CAPITAL: {t}"
            );
        }
        let expected = [
            crate::infra::trace::tag::ASSESSMENT_START,
            crate::infra::trace::tag::LLM_REQUEST,
            crate::infra::trace::tag::LLM_RESPONSE,
            crate::infra::trace::tag::DECISION_EXECUTE,
            crate::infra::trace::tag::PROVIDER_SELECTED,
            crate::infra::trace::tag::TOOL_ATTEMPT,
            crate::infra::trace::tag::TOOL_HTTP_CALL,
            crate::infra::trace::tag::TOOL_RESULT,
            crate::infra::trace::tag::HARNESS_FEEDBACK,
        ];
        let mut pos = 0;
        for want in expected {
            match tags[pos..].iter().position(|t| t == want) {
                Some(found) => pos += found + 1,
                None => panic!("missing tag {want} in order; got: {tags:?}"),
            }
        }
        // No secret values anywhere in the trace payloads.
        let blob = serde_json::to_string(&*log.lock().unwrap()).unwrap();
        assert!(
            !blob.contains("Bearer eyJ"),
            "credential leaked into trace"
        );
    }

    #[test]
    fn parse_miss_is_flagged_and_explained() {
        use std::sync::{Arc, Mutex};
        use crate::agent::executor::StubExecutor;
        // Unparseable-but-nonempty tool output: the trace must flag the
        // miss, and the model must get a Parse recovery note instead of
        // silence (which previously caused re-probing loops).
        let (tools, caps, state) = harness(&["nmap"]);
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::Execute {
                capability: "network.port_scan".into(),
                target: "10.0.0.1".into(),
                options: OptionSet::new(),
                reason: "scan".into(),
            },
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let log: Arc<Mutex<Vec<crate::infra::trace::TraceEntry>>> =
            Arc::new(Mutex::new(Vec::new()));
        let log2 = Arc::clone(&log);
        let rt = AgentRuntime::new(model, &tools, &caps, &state)
            .with_executor(Arc::new(StubExecutor::success("nmap", "total nonsense, not xml")))
            .with_tracer(move |e| log2.lock().unwrap().push(e));
        let _ = rt.investigate(Target::new("10.0.0.1"));
        let log = log.lock().unwrap();
        let miss = log.iter().find(|e| {
            e.tag == crate::infra::trace::tag::PARSER_RESULT
                && e.data.get("parse_miss").and_then(|v| v.as_bool()) == Some(true)
        });
        assert!(miss.is_some(), "parse miss must be flagged in trace");
    }

    #[test]
    fn runtime_builds_views_through_context_manager() {
        use std::sync::{Arc, Mutex};

        // Records every ContextView the model receives, then delegates to
        // the scripted stub. Shares the log via Arc<Mutex> (provider is Send).
        struct Capturing {
            inner: StubProvider,
            views: Arc<Mutex<Vec<ContextView>>>,
        }
        impl ModelProvider for Capturing {
            fn name(&self) -> &str {
                "capturing"
            }
            fn decide(&self, ctx: &ContextView) -> Result<Decision, ModelError> {
                self.views.lock().unwrap().push(ctx.clone());
                self.inner.decide(ctx)
            }
            fn chat(&self, system: &str, user: &str) -> Result<String, ModelError> {
                self.inner.chat(system, user)
            }
        }

        let (tools, caps, state) = harness(&["nmap"]);
        let views: Arc<Mutex<Vec<ContextView>>> = Arc::new(Mutex::new(Vec::new()));
        let model = Capturing {
            inner: StubProvider::new(vec![
                Decision::Execute {
                    capability: "network.port_scan".into(),
                    target: "10.0.0.1".into(),
                    options: OptionSet::new(),
                    reason: "ports unknown".into(),
                },
                Decision::CreateHypothesis {
                    statement: "SSH exposed".into(),
                    confidence: "low".into(),
                },
                Decision::Finish {
                    reason: "enough for the test".into(),
                },
            ]),
            views: views.clone(),
        };
        let rt = AgentRuntime::new(Box::new(model), &tools, &caps, &state);
        let res = rt.investigate(Target::new("10.0.0.1"));
        assert!(matches!(res.finish_reason, FinishReason::ModelFinished(_)));

        let seen = views.lock().unwrap().clone();
        assert_eq!(
            seen.len(),
            3,
            "one view per model call (execute, hypothesis, finish)"
        );

        // Step 0: empty memory, capabilities visible.
        assert!(seen[0].prior_actions.is_empty());
        assert!(seen[0].observations.is_empty()); // parsers arrive in Phase 5
        assert!(seen[0]
            .available_capabilities
            .contains(&"network.port_scan".to_string()));

        // Step 1: the execute decision is in memory.
        assert_eq!(seen[1].prior_actions.len(), 1);
        assert_eq!(
            seen[1].prior_actions[0],
            "network.port_scan on 10.0.0.1 via nmap [INEFFECTIVE] — ports unknown"
        );
    }

    #[test]
    fn parsed_output_flows_to_model_and_events() {
        use crate::agent::events::AgentEvent;
        use crate::agent::executor::StubExecutor;
        use std::cell::RefCell;

        // nmap XML fixture — what `-oX -` writes to stdout.
        let nmap_xml = "<?xml version=\"1.0\"?>\
<nmaprun scanner=\"nmap\"><host><status state=\"up\"/>\
<address addr=\"10.0.0.1\" addrtype=\"ipv4\"/><hostnames><hostname name=\"web01\" type=\"PTR\"/></hostnames>\
<ports><port protocol=\"tcp\" portid=\"22\"><state state=\"open\"/>\
<service name=\"ssh\" product=\"OpenSSH\" version=\"8.9p1\"/></port>\
<port protocol=\"tcp\" portid=\"80\"><state state=\"open\"/>\
<service name=\"http\" product=\"nginx\" version=\"1.24.0\"/></port></ports></host></nmaprun>";

        let (tools, caps, state) = harness(&["nmap"]);
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::Execute {
                capability: "network.service_detection".into(),
                target: "10.0.0.1".into(),
                options: OptionSet::new(),
                reason: "identify services".into(),
            },
            Decision::CreateHypothesis {
                statement: "outdated SSH may be exploitable".into(),
                confidence: "low".into(),
            },
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state)
            .with_executor(Arc::new(StubExecutor::success("nmap", nmap_xml)));
        let seen = RefCell::new(Vec::new());
        let res = rt.investigate_with(Target::new("10.0.0.1"), &mut |ev| {
            seen.borrow_mut().push(ev)
        });
        let seen = seen.into_inner();

        // Observations reached the event stream.
        let obs_events: Vec<_> = seen
            .iter()
            .filter_map(|e| match e {
                AgentEvent::ObservationAdded { summary } => Some(summary.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(obs_events.len(), 3, "hostname + 2 ports");
        assert!(obs_events
            .iter()
            .any(|s| s.contains("port 22/tcp open (ssh)")));
        assert!(obs_events.iter().any(|s| s.contains("nginx 1.24.0")));

        // One tool result recorded, executed successfully.
        assert_eq!(res.tool_results.len(), 1);
        assert!(res.tool_results[0].success());
        assert_eq!(res.tool_results[0].tool_id, "nmap");
    }

    #[test]
    fn full_loop_surfaces_unknowns_and_suggestions_to_the_model() {
        use crate::agent::executor::StubExecutor;
        use std::sync::{Arc, Mutex};

        // nmap output discovering an http port → AssessmentState gets
        // host+port+graph nodes → completeness gate sees high-value
        // unresolved objectives (http.probe via httpx is available) and
        // rejects the first Finish proposal. Intentional behavior change:
        // Finish is gated, not immediate.
        let nmap_xml = "<nmaprun><host><address addr=\"10.0.0.1\" addrtype=\"ipv4\"/>\
<ports><port protocol=\"tcp\" portid=\"80\"><state state=\"open\"/>\
<service name=\"http\" product=\"nginx\" version=\"1.24.0\"/></port></ports></host></nmaprun>";

        struct Capturing {
            inner: StubProvider,
            views: Arc<Mutex<Vec<ContextView>>>,
        }
        impl ModelProvider for Capturing {
            fn name(&self) -> &str {
                "capturing"
            }
            fn decide(&self, ctx: &ContextView) -> Result<Decision, ModelError> {
                self.views.lock().unwrap().push(ctx.clone());
                self.inner.decide(ctx)
            }
            fn chat(&self, system: &str, user: &str) -> Result<String, ModelError> {
                self.inner.chat(system, user)
            }
        }

        let (tools, caps, state) = harness(&["nmap", "httpx", "nuclei"]);
        let views: Arc<Mutex<Vec<ContextView>>> = Arc::new(Mutex::new(Vec::new()));
        let model = Capturing {
            inner: StubProvider::new(vec![
                Decision::Execute {
                    capability: "network.service_detection".into(),
                    target: "10.0.0.1".into(),
                    options: OptionSet::new(),
                    reason: "identify services".into(),
                },
                Decision::Finish {
                    reason: "loop verified".into(),
                },
            ]),
            views: views.clone(),
        };
        let rt = AgentRuntime::new(Box::new(model), &tools, &caps, &state)
            .with_executor(Arc::new(StubExecutor::success("nmap", nmap_xml)));
        let res = rt.investigate(Target::new("10.0.0.1"));
        assert!(matches!(res.finish_reason, FinishReason::ModelFinished(_)));

        let seen = views.lock().unwrap().clone();
        // Scripted Finish is denied until the denial budget exhausts (gated
        // completion), so more than the 2 scripted views are observed.
        assert!(seen.len() > 2, "finish gating should add views, got {}", seen.len());

        // After the nmap result was parsed:
        let step1 = &seen[1];
        assert!(
            step1
                .observations
                .iter()
                .any(|o| o.contains("nginx 1.24.0")),
            "parsed observation visible: {:?}",
            step1.observations
        );
    }

    #[test]
    fn events_fire_in_loop_order_including_rejection() {
        use crate::agent::events::AgentEvent;
        use std::cell::RefCell;

        let (tools, caps, state) = harness(&["nmap"]);
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::Execute {
                capability: "network.port_scan".into(),
                target: "10.0.0.1".into(),
                options: OptionSet::new(),
                reason: "r".into(),
            },
            Decision::Execute {
                capability: "cloud.posture_audit".into(), // no provider installed
                target: "10.0.0.1".into(),
                options: OptionSet::new(),
                reason: "mistake".into(),
            },
            Decision::CreateHypothesis {
                statement: "h".into(),
                confidence: "low".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let seen = RefCell::new(Vec::new());
        let res = rt.investigate_with(Target::new("10.0.0.1"), &mut |ev| {
            seen.borrow_mut().push(ev)
        });
        let seen = seen.into_inner();

        assert!(matches!(seen[0], AgentEvent::InvestigationStarted { .. }));
        assert!(seen.contains(&AgentEvent::StepStarted { step: 0 }));
        assert!(seen.iter().any(|e| matches!(e,
            AgentEvent::CapabilityRequested { capability, target, reason, model_secs, .. }
                if capability == "network.port_scan"
                    && target == "10.0.0.1"
                    && reason == "r"
                    && *model_secs >= 0.0
        )));
        assert!(seen.contains(&AgentEvent::ProviderSelected {
            capability: "network.port_scan".into(),
            provider: "nmap".into(),
        }));
        assert!(seen
            .iter()
            .any(|e| matches!(e, AgentEvent::ActionRejected { .. })));
        assert!(seen.contains(&AgentEvent::HypothesisAdded {
            id: 1,
            statement: "h".into(),
            confidence: "low".into(),
        }));
        assert!(matches!(seen.last(), Some(AgentEvent::Finished { .. })));
        // Rejection consumed no step: 1 execute + 1 hypothesis.
        assert_eq!(res.steps_taken, 2);
    }

    #[test]
    fn out_of_scope_targets_are_rejected_before_execution() {
        // The itsecgames/mmebvba case: a co-hosted site discovered during
        // the investigation must NOT become an active assessment target.
        use crate::agent::events::AgentEvent;
        use std::cell::RefCell;

        let (tools, caps, state) = harness(&["httpx"]);
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::Execute {
                capability: "http.probe".into(),
                target: "http://mmebvba.com/".into(), // discovered, not declared
                options: OptionSet::new(),
                reason: "probe the co-hosted site".into(),
            },
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let seen = RefCell::new(Vec::new());
        let res = rt.investigate_with(Target::new("www.itsecgames.com"), &mut |ev| {
            seen.borrow_mut().push(ev)
        });
        let seen = seen.into_inner();

        // Rejected with a distinct scope message…
        let rejection = seen
            .iter()
            .find_map(|e| match e {
                AgentEvent::ActionRejected { reason } => Some(reason.clone()),
                _ => None,
            })
            .expect("scope violation must be rejected");
        assert!(
            rejection.contains("outside assessment scope"),
            "got: {rejection}"
        );
        // …before any provider was selected or tool executed.
        assert!(!seen
            .iter()
            .any(|e| matches!(e, AgentEvent::ProviderSelected { .. })));
        assert!(!seen
            .iter()
            .any(|e| matches!(e, AgentEvent::ToolExecuted { .. })));
        assert_eq!(res.tool_results.len(), 0);
        assert_eq!(res.steps_taken, 0);
        // In-scope subdomain paths remain executable (sanity).
        let model2: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::Execute {
                capability: "http.probe".into(),
                target: "http://www.itsecgames.com/bWAPP/".into(),
                options: OptionSet::new(),
                reason: "probe in-scope path".into(),
            },
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let rt2 = AgentRuntime::new(model2, &tools, &caps, &state);
        let res2 = rt2.investigate(Target::new("www.itsecgames.com"));
        assert_eq!(res2.tool_results.len(), 1, "in-scope path must execute");
    }

    #[test]
    fn options_flow_through_translation_into_provider_argv() {
        // Semantic options from the model become provider flags via the
        // trusted binding table — never raw model input in argv.
        use crate::agent::executor::{ProcessOutput, RecordingExecutor};

        let (tools, caps, state) = harness(&["nmap"]);
        let mut options = OptionSet::new();
        options.insert("ports".into(), OptionValue::Str("80,443".into()));
        options.insert("intensity".into(), OptionValue::Str("fast".into()));
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::Execute {
                capability: "network.port_scan".into(),
                target: "10.0.0.1".into(),
                options,
                reason: "focused scan".into(),
            },
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let shared = Arc::new(RecordingExecutor {
            calls: std::sync::Mutex::new(Vec::new()),
            output: ProcessOutput {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
                timed_out: false,
                error: None,
            },
        });
        let rt = AgentRuntime::new(model, &tools, &caps, &state).with_executor(shared.clone());
        let res = rt.investigate(Target::new("10.0.0.1"));
        assert_eq!(res.tool_results.len(), 1);
        let calls = shared.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (_exe, argv) = &calls[0];
        assert!(argv.contains(&"-p".to_string()));
        assert!(argv.contains(&"80,443".to_string()));
        assert!(
            argv.contains(&"-T4".to_string()),
            "intensity=fast → -T4: {argv:?}"
        );
        // No raw model text ever appears as an ad-hoc flag.
        assert!(!argv.iter().any(|a| a.starts_with("--")));
    }

    #[test]
    fn provider_fallback_in_the_loop_when_primary_unavailable() {
        // nmap absent, naabu installed → the loop still executes
        // network.port_scan, through naabu.
        use crate::agent::events::AgentEvent;
        use std::cell::RefCell;

        let (tools, caps, state) = harness(&["naabu"]);
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::Execute {
                capability: "network.port_scan".into(),
                target: "10.0.0.1".into(),
                options: OptionSet::new(),
                reason: "scan".into(),
            },
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state).with_executor(Arc::new(
            crate::agent::executor::StubExecutor::success("naabu", "{}"),
        ));
        let seen = RefCell::new(Vec::new());
        let res = rt.investigate_with(Target::new("10.0.0.1"), &mut |ev| {
            seen.borrow_mut().push(ev)
        });
        let seen = RefCell::into_inner(seen);
        assert!(seen.contains(&AgentEvent::ProviderSelected {
            capability: "network.port_scan".into(),
            provider: "naabu".into(),
        }));
        assert_eq!(res.tool_results.len(), 1);
        assert_eq!(res.tool_results[0].tool_id, "naabu");
        assert_eq!(res.planned_actions[0].provider, "naabu");
    }

    #[test]
    fn invalid_options_are_rejected_and_fed_back() {
        // A model passing an undeclared option gets a distinct
        // invalid-arguments rejection and nothing executes.
        use crate::agent::events::AgentEvent;
        use std::cell::RefCell;

        let (tools, caps, state) = harness(&["nmap"]);
        let mut options = OptionSet::new();
        options.insert("flags".into(), OptionValue::Str("--privileged".into()));
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::Execute {
                capability: "network.port_scan".into(),
                target: "10.0.0.1".into(),
                options,
                reason: "smuggle flags".into(),
            },
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let seen = RefCell::new(Vec::new());
        let res = rt.investigate_with(Target::new("10.0.0.1"), &mut |ev| {
            seen.borrow_mut().push(ev)
        });
        let seen = RefCell::into_inner(seen);
        let rejection = seen
            .iter()
            .find_map(|e| match e {
                AgentEvent::ActionRejected { reason } => Some(reason.clone()),
                _ => None,
            })
            .expect("invalid arguments must be rejected");
        assert!(
            rejection.contains("unknown option `flags`"),
            "got: {rejection}"
        );
        assert_eq!(res.tool_results.len(), 0);
        assert_eq!(res.steps_taken, 0);
    }

    #[test]
    fn report_and_update_finding_flow_through_drive() {
        use crate::agent::events::AgentEvent;
        use std::cell::RefCell;
        let (tools, caps, state) = harness(&[]);
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::ReportFinding {
                severity: "high".into(),
                title: "SQLi in login".into(),
                target: "".into(),
                detail: "error-based".into(),
            },
            Decision::UpdateFinding {
                id: 1,
                status: "confirmed".into(),
                note: "validated with sleep".into(),
            },
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let seen = RefCell::new(Vec::new());
        let res = rt.investigate_with(Target::new("10.0.0.1"), &mut |ev| {
            seen.borrow_mut().push(ev)
        });
        let seen = RefCell::into_inner(seen);
        let recorded: Vec<_> = seen
            .iter()
            .filter_map(|e| match e {
                AgentEvent::FindingRecorded { status, .. } => Some(status.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(recorded, vec!["open".to_string(), "confirmed".to_string()]);
        // Blank report target resolves to the assessment target.
        let first_target = seen.iter().find_map(|e| match e {
            AgentEvent::FindingRecorded { target, .. } => Some(target.clone()),
            _ => None,
        });
        assert_eq!(first_target.as_deref(), Some("10.0.0.1"));
        assert!(matches!(res.finish_reason, FinishReason::ModelFinished(_)));
    }

    #[test]
    fn unknown_finding_id_and_ephemeral_vault_value_are_corrected_not_stored() {
        use crate::agent::events::AgentEvent;
        use std::cell::RefCell;
        let (tools, caps, state) = harness(&[]);
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::UpdateFinding {
                id: 99,
                status: "confirmed".into(),
                note: "".into(),
            },
            Decision::VaultStore {
                key: "session".into(),
                value: jwt.into(),
                kind: "secret".into(),
                source: "cookie".into(),
            },
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let seen = RefCell::new(Vec::new());
        rt.investigate_with(Target::new("10.0.0.1"), &mut |ev| {
            seen.borrow_mut().push(ev)
        });
        let seen = RefCell::into_inner(seen);
        assert!(
            !seen.iter().any(|e| matches!(
                e,
                AgentEvent::FindingRecorded { .. } | AgentEvent::VaultStored { .. }
            )),
            "nothing must be recorded for unknown ids / ephemeral values"
        );
    }

    #[test]
    fn vault_store_and_recall_never_leak_values_to_events() {
        use crate::agent::events::AgentEvent;
        use std::cell::RefCell;
        // Redirect the state dir so the test vault never touches the
        // real %APPDATA%\medusa.
        let old_appdata = std::env::var_os("APPDATA");
        let tmp = std::env::temp_dir().join(format!("medusa-vault-test-{}", std::process::id()));
        std::env::set_var("APPDATA", &tmp);
        let (tools, caps, state) = harness(&[]);
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::VaultStore {
                key: "db_password".into(),
                value: "s3cr3t-vault-value".into(),
                kind: "password".into(),
                source: "env dump".into(),
            },
            Decision::VaultRecall {
                query: "db_password".into(),
            },
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let seen = RefCell::new(Vec::new());
        rt.investigate_with(Target::new("10.9.9.9"), &mut |ev| {
            seen.borrow_mut().push(ev)
        });
        let seen = RefCell::into_inner(seen);
        assert!(seen.iter().any(|e| matches!(
            e,
            AgentEvent::VaultStored { key, .. } if key == "db_password"
        )));
        assert!(seen.iter().any(|e| matches!(
            e,
            AgentEvent::VaultRecalled { key } if key == "db_password"
        )));
        let debug: String = seen.iter().map(|e| format!("{e:?}")).collect();
        assert!(
            !debug.contains("s3cr3t-vault-value"),
            "vault values must never reach the event stream"
        );
        // Restore the real state dir for the rest of the suite.
        match old_appdata {
            Some(v) => std::env::set_var("APPDATA", v),
            None => std::env::remove_var("APPDATA"),
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn auto_compaction_triggers_at_threshold_and_preserves_registry() {
        use crate::agent::events::AgentEvent;
        use crate::agent::model::{ContextView, ModelError, UsageReport};
        use std::cell::RefCell;
        use std::sync::{Arc, Mutex};

        /// Scripted provider whose FIRST decision reports a hot window
        /// (9000/10000 tokens) and the rest report real estimates.
        /// Records how many registry findings each decision's view held.
        struct HotProvider {
            script: Vec<Decision>,
            pos: Mutex<usize>,
            hot_calls: Mutex<usize>,
            seen_findings: Arc<Mutex<Vec<usize>>>,
        }
        impl ModelProvider for HotProvider {
            fn name(&self) -> &str {
                "hot"
            }
            fn decide(&self, ctx: &ContextView) -> Result<Decision, ModelError> {
                self.seen_findings.lock().unwrap().push(ctx.findings.len());
                let mut pos = self.pos.lock().unwrap();
                let i = *pos;
                *pos += 1;
                Ok(self.script.get(i).cloned().unwrap_or(Decision::Finish {
                    reason: "script exhausted".into(),
                }))
            }
            fn decide_reported(
                &self,
                ctx: &ContextView,
            ) -> (Result<Decision, ModelError>, UsageReport) {
                let outcome = self.decide(ctx);
                let mut hot = self.hot_calls.lock().unwrap();
                let n = *hot;
                *hot += 1;
                if n == 0 {
                    (
                        outcome,
                        UsageReport {
                            prompt_tokens: 9000,
                            completion_tokens: 0,
                            total_tokens: 9000,
                            cached_tokens: 0,
                            estimated: false,
                        },
                    )
                } else {
                    let chars = serde_json::to_string(ctx).map(|s| s.len()).unwrap_or(0);
                    (outcome, UsageReport::estimate(chars, 0))
                }
            }
            fn chat(&self, _system: &str, user: &str) -> Result<String, ModelError> {
                let snip: String = user.chars().take(60).collect();
                Ok(format!("SUMMARY: {snip}"))
            }
        }

        let (tools, caps, state) = harness(&[]);
        let seen_findings: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
        let model: Box<dyn ModelProvider> = Box::new(HotProvider {
            script: vec![
                Decision::ReportFinding {
                    severity: "High".into(),
                    title: "kept finding".into(),
                    target: "".into(),
                    detail: "must survive".into(),
                },
                Decision::Narrate {
                    text: "progress".into(),
                },
                Decision::Finish {
                    reason: "done".into(),
                },
            ],
            pos: Mutex::new(0),
            hot_calls: Mutex::new(0),
            seen_findings: Arc::clone(&seen_findings),
        });
        let rt = AgentRuntime::new(model, &tools, &caps, &state)
            .with_context_window(10_000)
            .with_compaction_threshold(80);
        let seen = RefCell::new(Vec::new());
        let res = rt.investigate_with(Target::new("10.0.0.1"), &mut |ev| {
            seen.borrow_mut().push(ev)
        });
        let seen = RefCell::into_inner(seen);
        let (freed, fallback) = seen
            .iter()
            .find_map(|e| match e {
                AgentEvent::Compacted {
                    freed_tokens,
                    fallback,
                    ..
                } => Some((*freed_tokens, *fallback)),
                _ => None,
            })
            .expect("threshold crossing must compact");
        assert!(!fallback, "summarizer succeeds — no fallback");
        assert!(freed > 0, "compaction must free tokens");
        // The registry finding must survive compaction: the first decide
        // ran before it was reported (0), and every decide after it —
        // including the one past the compaction — still sees it (1). The
        // loop may re-decide several times because the completeness engine
        // rejects an early finish, so assert the invariant, not a fixed
        // call count.
        let seen = seen_findings.lock().unwrap();
        assert_eq!(seen[0], 0, "first decide precedes the finding");
        assert!(
            seen[1..].iter().all(|&n| n == 1),
            "finding must stay visible across compaction: {seen:?}"
        );
        assert!(matches!(res.finish_reason, FinishReason::ModelFinished(_)));
    }
}
