//! Phase 2: the ContextManager — budgeted, relevance-filtered model context.
//!
//! The investigation loop records everything (actions, hypotheses, parsed
//! observations); the ContextManager decides what the model *sees* on each
//! step. Selection signals in Phase 2:
//!
//! * **Token budgeting** — a char-approximated ceiling (~4 chars â‰ˆ 1 token)
//!   on the serialized decision prompt, so long investigations cannot bloat
//!   context until the model degrades.
//! * **Recency filtering** — within each category the newest records win
//!   (the freshest state is the most relevant while iterating).
//! * **Deduplication** — identical observation summaries collapse; tools
//!   re-run on overlapping scope must not pay context twice.
//! * **Never-elided essentials** — target, step, the capability action
//!   space, and the last error always reach the model. A model that cannot
//!   see what it may do, or why its last action failed, cannot recover.
//!
//! Richer relevance (world-model affinity, hypothesis linkage) arrives with
//! Phase 3/6; the [`ContextManager`] interface stays the same.
//!
//! Purity: recording and selection are pure — no I/O, no events, no clocks.
//! The runtime decides when to record and which events to emit.

use serde::{Deserialize, Serialize};

use super::model::ContextView;
use super::model::TranscriptMsg;
use super::runtime::Target;

/// One normalized finding from a tool run. Parsers (Phase 5) produce these;
/// raw scanner output never reaches the model directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub id: usize,
    /// The asset the observation is about (host, URL, path, ...).
    pub target: String,
    /// Human- and model-readable one-liner, e.g. "10.0.0.1 port 22 open (ssh)".
    pub summary: String,
    /// Capability that produced it, e.g. "network.port_scan".
    pub source: String,
    /// Investigation step at which it was recorded.
    pub step: usize,
}

/// One registry finding, reported by the model via `report_finding`.
/// Unlike observations (distilled tool output that budgets and compaction
/// may elide), findings are NEVER elided from the view: the model must
/// not lose track of confirmed vulnerabilities in a long investigation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: usize,
    /// Critical | High | Medium | Low | Info (normalized at parse).
    pub severity: String,
    pub title: String,
    /// The asset the finding is about.
    pub target: String,
    /// Capability that produced the evidence, e.g. "web.vulnerability_scan".
    pub source: String,
    /// What/where/impact in a few sentences.
    pub detail: String,
    /// open | confirmed | false_positive.
    pub status: String,
    /// Investigation step at which it was reported.
    pub step_found: usize,
    /// Investigation step of the last status/detail change.
    pub step_updated: usize,
}

/// A validated execute decision. Phase 4 executes these for real; until
/// then they record that the loop resolved capability → provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionRecord {    pub step: usize,
    pub capability: String,
    pub provider: String,
    pub target: String,
    pub reason: String,
    /// Did the execution actually produce usable coverage? `false` for
    /// failed runs and for exit-0-but-ineffective runs (sqlmap "no
    /// parameter(s) found", trivy FATAL on a URL target). The planner
    /// only counts effective actions as resolving an unknown — an
    /// ineffective run must not let the investigation declare victory.
    #[serde(default = "default_true")]
    pub effective: bool,
}

fn default_true() -> bool {
    true
}

/// Char-approximated context ceiling for one decision prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenBudget {
    /// Maximum serialized characters (~4 chars â‰ˆ 1 token).
    pub max_chars: usize,
}

impl Default for TokenBudget {
    fn default() -> Self {
        // ≈ 12k tokens — generous enough that payload-verification tools
        // (http.request bodies, rendered SSTI/SQLi output) reach the model
        // in an analyzable form, while still eliding long before provider
        // context limits.
        Self { max_chars: 48_000 }
    }
}

/// What the budget cost the model this step (telemetry for tests/debug).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BudgetReport {
    /// Serialized size of the final view.
    pub total_chars: usize,
    pub elided_observations: usize,
    pub elided_evidence: usize,
    pub elided_narrations: usize,
    pub elided_actions: usize,
}

/// Investigation memory + the selection policy that turns it into a
/// [`ContextView`]. One instance per investigation; the runtime owns it.
/// Serializable so the runtime can snapshot it whole to disk (see
/// [`save`]/[`load`]) and restore it on a session reopen, instead of
/// relying only on the session log's lossy, field-by-field replay.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContextManager {
    observations: Vec<Observation>,
    actions: Vec<ActionRecord>,
    last_error: Option<String>,
    error_history: Vec<String>,
    budget: TokenBudget,
    /// User/assistant turns (unified chat+agent loop). Unbounded: the
    /// model sees the full dialogue verbatim. Context-overflow handling
    /// (compaction) is a future concern, not a silent truncation here.
    conversation: Vec<crate::agent::model::ChatTurn>,
    /// Raw (truncated) tool outputs — the undistilled evidence the model
    /// sees alongside parsed observations. Ring buffer: newest
    /// executions win, capped in entries and per-entry chars.
    evidence: Vec<EvidenceEntry>,
    /// Updates the model already sent to the user this session
    /// (`narrate` decisions and turn-ending replies). Without this the
    /// model cannot tell what the user already knows and re-announces
    /// the same finding after every tool call.
    narrations: Vec<String>,
    /// Session findings registry (model-reported). Never elided from
    /// the view and never summarized away by compaction.
    findings: Vec<Finding>,
    /// Vault KEY NAMES visible in context (values never live here).
    /// Excluded from the snapshot: reloaded live from the per-target
    /// vault file, never from this persistence path.
    #[serde(skip)]
    vault_keys: Vec<String>,
    /// Recalled vault values for the NEXT decision only (`key=value`
    /// lines). Cleared by the runtime after one decision (least
    /// exposure); never persisted, never emitted.
    #[serde(skip)]
    vault_values: Vec<String>,
    /// Set when the conversation was compacted: the view carries a note
    /// pointing the model at the summary turn.
    compacted: bool,
    /// How many times auto/manual compaction ran this session.
    pub compaction_count: usize,
    /// Count of findings the user had already been told about as of the
    /// last narration. Findings appended beyond this count are ones the
    /// model recorded but has NOT yet announced — the harness turns that
    /// gap into a `pending_narration` directive in the view (see
    /// [`Self::pending_narration_note`]) so a confirmed win is never left
    /// sitting silently in state while the model moves on to the next tool.
    #[serde(default)]
    findings_narrated: usize,
    /// Append-only wire transcript (see [`TranscriptMsg`]): conversation
    /// turns plus per-step event messages, oldest first. Pushed at
    /// recording time, never rewritten except at the compaction boundary,
    /// so consecutive requests share a byte-identical prefix. Persisted
    /// with the snapshot — resume restores identical history.
    #[serde(default)]
    transcript: Vec<TranscriptMsg>,
    /// Model-call failure note staged for the NEXT step's tail (see
    /// [`Self::stage_model_note`]). Never touches same-step retries, so
    /// retries stay byte-identical.
    #[serde(default)]
    staged_model_note: Option<String>,
    /// First step at which `staged_model_note` may appear.
    #[serde(default)]
    staged_note_step: usize,
    /// Assessment mode for the brief (`true` = autonomous CLI assess).
    /// Set once per turn by the runtime; stable within a session.
    #[serde(default)]
    autonomous: bool,
}

/// One raw tool output kept for model visibility.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct EvidenceEntry {
    tool_id: String,
    target: String,
    output: String,
}

/// Per-entry raw-output cap (chars). Long outputs keep their head —
/// findings and status lines come first in every tool's format. Raised
/// for evidence-heavy tools the model needs to reason over (response
/// bodies, payload render results) rather than just acknowledge.
const EVIDENCE_ENTRY_CAP: usize = 12_000;
/// How many raw outputs ride the context. Newest last.
const MAX_EVIDENCE_ENTRIES: usize = 10;
/// Observations retained across a compaction. Findings carry the durable
/// conclusions; observations past this cap are expendable history.
const MAX_OBSERVATIONS_AFTER_COMPACT: usize = 50;
/// Transcript messages retained verbatim across a compaction, newest
/// first fill (Codex keeps ~20k tokens of recent messages; opencode
/// ~15k). The summary carries the rest.
const TRANSCRIPT_TAIL_CHARS: usize = 20_000;
/// Tools whose raw output the model must READ in full, not just
/// acknowledge, so they get the whole per-entry allowance instead of
/// half: `medusa-http` (payload-verification bodies — the rendered
/// SSTI/SQLi/IDOR result often sits mid-page) and `medusa-research`
/// (fetched source/docs/CVE pages — the exact line that matters, e.g. a
/// challenge's solve condition, can sit anywhere in the extract).
const EVIDENCE_FULL_CAP_TOOLS: &[&str] = &["medusa-http", "medusa-research"];
/// How many user-facing updates the model remembers sending.
const MAX_NARRATIONS: usize = 15;
const MAX_ERROR_HISTORY: usize = 6;
const ERROR_HISTORY_ENTRY_CAP: usize = 240;
/// Effective actions with no new finding before the harness warns the
/// model it is likely thrashing (permuting the same attempt against an
/// unchanged success check) and should change approach. Tuned so a
/// normal multi-step exploit chain does not trip it, but an hour of
/// payload permutations does.
const STALL_ACTIONS_WITHOUT_FINDING: usize = 8;

fn evidence_line(e: &EvidenceEntry) -> String {
    format!("[{}] {}:\n{}", e.tool_id, e.target, e.output)
}

impl ContextManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_budget(budget: TokenBudget) -> Self {
        Self {
            budget,
            ..Self::default()
        }
    }

    /// Record a parsed observation. Exact-duplicate summaries are collapsed
    /// (the first occurrence is kept). Returns the observation id. A new
    /// observation also appends one transcript message (cache-stable: the
    /// stored line, never re-rendered later).
    pub fn add_observation(
        &mut self,
        target: &str,
        summary: &str,
        source: &str,
        step: usize,
    ) -> usize {
        if let Some(existing) = self.observations.iter().find(|o| o.summary == summary) {
            return existing.id;
        }
        let id = self.observations.len() + 1;
        let obs = Observation {
            id,
            target: target.to_string(),
            summary: summary.to_string(),
            source: source.to_string(),
            step,
        };
        let line = observation_line(&obs);
        self.observations.push(obs);
        self.push_user(line);
        id
    }

    /// Record a validated execute decision. Also appends one transcript
    /// message (the model's own action, assistant role).
    pub fn add_action(
        &mut self,
        step: usize,
        capability: String,
        provider: String,
        target: String,
        reason: String,
        effective: bool,
    ) {
        let record = ActionRecord {
            step,
            capability,
            provider,
            target,
            reason,
            effective,
        };
        let line = action_line(&record);
        self.actions.push(record);
        self.push_assistant(line);
    }

    /// Feedback channel for self-correction: policy rejections and model
    /// errors. Always included in the next view.
    pub fn set_last_error(&mut self, error: Option<String>) {
        if let Some(e) = &error {
            let trimmed = e.trim();
            if !trimmed.is_empty() {
                let entry: String = trimmed.chars().take(ERROR_HISTORY_ENTRY_CAP).collect();
                if self.error_history.last().map(String::as_str) != Some(entry.as_str()) {
                    self.error_history.push(entry);
                    let overflow = self
                        .error_history
                        .len()
                        .saturating_sub(MAX_ERROR_HISTORY);
                    if overflow > 0 {
                        self.error_history.drain(0..overflow);
                    }
                }
            }
        }
        self.last_error = error;
    }

    /// Read-only view of the current feedback line (repeat-failure
    /// breaker remediation text). Full error stays in the ContextView.
    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    /// Open a turn: records the user message with an empty assistant
    /// reply. [`Self::end_turn`] fills the reply when the turn completes.
    /// The user text also opens the wire transcript.
    pub fn begin_turn(&mut self, user: &str) {
        self.conversation.push(crate::agent::model::ChatTurn {
            user: user.to_string(),
            assistant: String::new(),
        });
        self.push_user(user.to_string());
    }

    /// Close the turn opened by [`Self::begin_turn`] with the assistant
    /// text that ended it (reply or finish reason). Conversation only —
    /// the transcript already carries every decision as an assistant
    /// message (pushed by the runtime per decision), so pushing here
    /// would duplicate the reply.
    pub fn end_turn(&mut self, assistant: &str) {
        if let Some(last) = self.conversation.last_mut() {
            last.assistant = assistant.to_string();
        }
    }

    /// The most recent turn, if any. Used to dedupe session replay.
    pub fn last_turn(&self) -> Option<&crate::agent::model::ChatTurn> {
        self.conversation.last()
    }

    /// Fold a user message that arrived mid-turn into the conversation so
    /// the model sees it on its next decision. Unlike [`Self::begin_turn`]
    /// this does not imply a turn boundary — the running turn continues;
    /// its closing [`Self::end_turn`] still fills the latest turn's reply.
    pub fn inject_user_message(&mut self, text: &str) {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return;
        }
        self.conversation.push(crate::agent::model::ChatTurn {
            user: trimmed.to_string(),
            assistant: String::new(),
        });
        self.push_user(trimmed.to_string());
    }

    /// Full conversation (oldest first). Used for compaction materials
    /// and window estimates — never serialized to session records.
    pub fn conversation(&self) -> &[crate::agent::model::ChatTurn] {
        &self.conversation
    }

    /// Append a user message to the wire transcript. Empty text is
    /// ignored. Never rewrites history — the cache prefix property
    /// depends on this being append-only between compactions.
    pub fn push_user(&mut self, content: String) {
        if content.trim().is_empty() {
            return;
        }
        self.transcript
            .push(crate::agent::model::TranscriptMsg::user(content));
    }

    /// Append an assistant message to the wire transcript. Empty text is
    /// ignored. The runtime calls this once per model decision with the
    /// rendered decision, so the model's own prior outputs replay
    /// verbatim on the next step.
    pub fn push_assistant(&mut self, content: String) {
        if content.trim().is_empty() {
            return;
        }
        self.transcript
            .push(crate::agent::model::TranscriptMsg::assistant(content));
    }

    /// The wire transcript, oldest first. Byte-stable across steps:
    /// callers must only ever extend the returned prefix by appending.
    pub fn transcript(&self) -> &[crate::agent::model::TranscriptMsg] {
        &self.transcript
    }

    /// Assessment mode for the brief. Set once per turn by the runtime.
    pub fn set_autonomous(&mut self, autonomous: bool) {
        self.autonomous = autonomous;
    }

    /// Stage a model-call failure note for the NEXT step's tail. The note
    /// is hidden from views built for `current_step` itself, so a
    /// same-step retry rebuilds a byte-identical request; it surfaces in
    /// the first view of a later step. Replaces any previously staged
    /// note. Cleared on turn end and compaction.
    pub fn stage_model_note(&mut self, note: String, current_step: usize) {
        if note.trim().is_empty() {
            return;
        }
        self.staged_note_step = current_step.saturating_add(1);
        self.staged_model_note = Some(note);
    }

    /// Drop any staged model note (turn end, give-up, compaction).
    pub fn clear_staged_model_note(&mut self) {
        self.staged_model_note = None;
    }

    /// Mark a replayed compaction (session reload): the model sees the
    /// continuity note without a new summary turn being fabricated.
    pub fn note_replayed_compaction(&mut self) {
        if !self.compacted {
            self.compacted = true;
            self.compaction_count += 1;
        }
    }

    /// Record one tool's raw output for model visibility. Truncated to
    /// the entry cap (head kept) unless the tool is a payload-verification
    /// tool that gets the full allowance; only the newest
    /// [`MAX_EVIDENCE_ENTRIES`] executions are retained. Empty outputs
    /// are skipped — the empty-success observation covers that case.
    pub fn add_evidence(&mut self, tool_id: &str, target: &str, output: &str) {
        let trimmed = output.trim();
        if trimmed.is_empty() {
            return;
        }
        let cap = if EVIDENCE_FULL_CAP_TOOLS.contains(&tool_id) {
            EVIDENCE_ENTRY_CAP
        } else {
            EVIDENCE_ENTRY_CAP / 2
        };
        let mut cut = cap.min(trimmed.len());
        while cut > 0 && !trimmed.is_char_boundary(cut) {
            cut -= 1;
        }
        let output = if cut < trimmed.len() {
            format!(
                "{}\n... [truncated, {} chars total]",
                &trimmed[..cut],
                trimmed.len()
            )
        } else {
            trimmed.to_string()
        };
        // Drop a byte-identical re-fetch of the same tool+target (e.g. the
        // model re-running `web.research` on the same URL and getting the
        // same windowed head): it adds no new information and a 12k dump
        // repeated several times just crowds the window. The existing
        // entry already rides the view. Compared AFTER truncation so the
        // stored (capped) forms are what's matched.
        if self
            .evidence
            .iter()
            .any(|e| e.tool_id == tool_id && e.target == target && e.output == output)
        {
            return;
        }
        let entry = EvidenceEntry {
            tool_id: tool_id.to_string(),
            target: target.to_string(),
            output,
        };
        let line = evidence_line(&entry);
        self.evidence.push(entry);
        // Transcript is append-only: ring eviction below affects the
        // legacy array only, never recorded messages.
        self.push_user(line);
        let overflow = self.evidence.len().saturating_sub(MAX_EVIDENCE_ENTRIES);
        if overflow > 0 {
            self.evidence.drain(0..overflow);
        }
    }

    /// Record an update sent to the user (narrate decision or turn-end
    /// reply). The model sees these so it does not re-announce findings
    /// it already reported. Newest kept, bounded. Also appends the text
    /// as an assistant transcript message (the model's own words).
    pub fn add_narration(&mut self, text: &str) {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return;
        }
        self.narrations.push(trimmed.to_string());
        self.push_assistant(trimmed.to_string());
        let overflow = self.narrations.len().saturating_sub(MAX_NARRATIONS);
        if overflow > 0 {
            self.narrations.drain(0..overflow);
        }
        // Everything confirmed so far has now been announced: clear the
        // pending-narration backlog so the nudge does not re-fire for
        // findings this narration already covered.
        self.findings_narrated = self.findings.len();
    }

    /// Directive injected into the view when findings have been recorded
    /// but not yet narrated: names them and tells the model to announce
    /// what it found before running the next tool. `None` when the user
    /// is already up to date. This is the harness-enforced half of the
    /// "communicate what you found" contract — it does not depend on the
    /// model remembering the system prompt.
    fn pending_narration_note(&self) -> Option<String> {
        let unnarrated = self.findings.get(self.findings_narrated..)?;
        if unnarrated.is_empty() {
            return None;
        }
        let names: Vec<String> = unnarrated
            .iter()
            .map(|f| format!("F{} {} ({})", f.id, f.title, f.target))
            .collect();
        Some(format!(
            "You have recorded {} finding(s) the user has NOT been told about yet: {}. \
             Before your next execute/web_search, send a `narrate` in plain language saying \
             what you found and what it means for the target. Do not restate findings already \
             listed in `narrations`.",
            names.len(),
            names.join("; ")
        ))
    }

    /// Directive injected when the agent has run many effective actions
    /// without recording a new finding — the signature of thrashing
    /// (permuting the same attempt against an unchanged success check).
    /// `None` until the threshold is crossed. Counts actions taken AFTER
    /// the most recent finding (or all actions when none exist yet).
    fn strategy_hint(&self) -> Option<String> {
        let last_finding_step = self.findings.iter().map(|f| f.step_found).max();
        let since = self
            .actions
            .iter()
            .filter(|a| last_finding_step.map_or(true, |s| a.step > s))
            .count();
        if since < STALL_ACTIONS_WITHOUT_FINDING {
            return None;
        }
        Some(format!(
            "You have run {since} actions with no NEW finding. If you are repeating variations of \
             the same attempt (same endpoint/payload class) against an unchanged success check, \
             STOP permuting — it is not working. Change approach: (1) read the target's own source \
             to learn the EXACT trigger — for an open-source app use `web.research` to fetch the \
             relevant source file (e.g. a raw GitHub URL) and read the precise condition, rather \
             than guessing; (2) if a plain HTTP request can reproduce what a browser would send, \
             prefer that over repeated browser loads; (3) try a fundamentally different vector. \
             Do not keep permuting the same payload."
        ))
    }

    fn recent_conversation(&self) -> Vec<crate::agent::model::ChatTurn> {
        self.conversation.clone()
    }

    pub fn observations(&self) -> &[Observation] {
        &self.observations
    }

    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Record a model-reported finding. Same title+target collapses to
    /// an update (detail refreshed, step bumped) so re-reporting never
    /// duplicates the registry. Returns the finding id.
    pub fn add_finding(
        &mut self,
        severity: &str,
        title: &str,
        target: &str,
        source: &str,
        detail: &str,
        step: usize,
    ) -> usize {
        if let Some(existing) = self
            .findings
            .iter_mut()
            .find(|f| f.title == title && f.target == target)
        {
            if !detail.trim().is_empty() {
                existing.detail = detail.to_string();
            }
            existing.severity = severity.to_string();
            existing.step_updated = step;
            return existing.id;
        }
        let id = self.findings.len() + 1;
        self.findings.push(Finding {
            id,
            severity: severity.to_string(),
            title: title.to_string(),
            target: target.to_string(),
            source: source.to_string(),
            detail: detail.to_string(),
            status: "open".to_string(),
            step_found: step,
            step_updated: step,
        });
        id
    }

    /// Re-insert a finding with its persisted id (session replay). Used
    /// only by rehydration; live reporting goes through `add_finding`.
    pub fn replay_finding(&mut self, finding: Finding) {
        if self.findings.iter().any(|f| f.id == finding.id) {
            return;
        }
        self.findings.push(finding);
        self.findings.sort_by_key(|f| f.id);
    }

    /// Change a finding's status. Returns false for an unknown id (the
    /// runtime feeds that back to the model as a correction).
    pub fn update_finding(&mut self, id: usize, status: &str, step: usize) -> bool {
        if let Some(f) = self.findings.iter_mut().find(|f| f.id == id) {
            f.status = status.to_string();
            f.step_updated = step;
            true
        } else {
            false
        }
    }

    /// One line per registry finding for the view. The FULL list rides
    /// every view — findings are never budgeted or elided.
    fn finding_lines(&self) -> Vec<String> {
        self.findings
            .iter()
            .map(|f| {
                let detail = if f.detail.trim().is_empty() {
                    String::new()
                } else {
                    format!(" — {}", f.detail)
                };
                format!(
                    "F{} [{}|{}] {} ({}){}",
                    f.id, f.severity, f.status, f.title, f.target, detail
                )
            })
            .collect()
    }

    /// Advertise vault key names to the model (values never enter the
    /// ContextManager — they ride one decision via `recall_vault_value`).
    pub fn set_vault_keys(&mut self, keys: Vec<String>) {
        self.vault_keys = keys;
    }

    /// Stage recalled `key=value` lines for the NEXT view only. The
    /// runtime clears them after one decision.
    pub fn recall_vault_value(&mut self, key: &str, value: &str) {
        self.vault_values.retain(|l| !l.starts_with(&format!("{key}=")));
        self.vault_values.push(format!("{key}={value}"));
    }

    pub fn clear_vault_values(&mut self) {
        self.vault_values.clear();
    }

    /// Compact the conversation: replace older turns with a model-written
    /// summary turn, drop the raw evidence ring (already distilled into
    /// observations/findings), and cap observations to the newest
    /// `MAX_OBSERVATIONS_AFTER_COMPACT`. Findings, vault keys, narrations,
    /// and actions survive verbatim — compaction must never lose track
    /// of what was confirmed or what the user was told.
    ///
    /// The wire transcript gets the same boundary treatment: the summary
    /// becomes the first exchange, then the most recent messages fitting
    /// `TRANSCRIPT_TAIL_CHARS` ride verbatim. A compaction is the one
    /// accepted cache reset; everything after it appends again.
    pub fn compact(&mut self, summary: &str, keep_turns: usize) {
        let keep = keep_turns.min(self.conversation.len());
        let tail: Vec<crate::agent::model::ChatTurn> =
            self.conversation[self.conversation.len() - keep..].to_vec();
        self.conversation = Vec::with_capacity(tail.len() + 1);
        self.conversation.push(crate::agent::model::ChatTurn {
            user: "[Earlier conversation compacted — read the assistant summary, then continue from the turns below.]".to_string(),
            assistant: summary.to_string(),
        });
        self.conversation.extend(tail);
        let mut kept: Vec<crate::agent::model::TranscriptMsg> = Vec::new();
        let mut used = 0usize;
        for m in self.transcript.iter().rev() {
            let cost = m.content.len().saturating_add(8);
            if !kept.is_empty() && used.saturating_add(cost) > TRANSCRIPT_TAIL_CHARS {
                break;
            }
            used = used.saturating_add(cost);
            kept.push(m.clone());
        }
        kept.reverse();
        self.transcript = vec![
            crate::agent::model::TranscriptMsg::user(
                "[Earlier context compacted — read the assistant summary, then continue.]".to_string(),
            ),
            crate::agent::model::TranscriptMsg::assistant(summary.to_string()),
        ];
        self.transcript.extend(kept);
        // A staged note refers to a pre-compaction step: drop it rather
        // than surfacing stale directives after the boundary.
        self.staged_model_note = None;
        self.evidence.clear();
        let overflow = self
            .observations
            .len()
            .saturating_sub(MAX_OBSERVATIONS_AFTER_COMPACT);
        if overflow > 0 {
            self.observations.drain(0..overflow);
        }
        self.compacted = true;
        self.compaction_count += 1;
    }

    pub fn was_compacted(&self) -> bool {
        self.compacted
    }

    pub fn actions(&self) -> &[ActionRecord] {
        &self.actions
    }

    /// Stable engagement brief: target, mode, capabilities, schemas,
    /// vault key names, findings registry. Byte-stable head — only the
    /// findings section at its end grows, append-only, so consecutive
    /// steps share the prefix.
    fn build_brief(
        &self,
        target: &Target,
        available_capabilities: &[String],
        unavailable_count: usize,
        capability_schemas: &[String],
    ) -> String {
        let mut out = String::new();
        out.push_str(&format!("TARGET: {}\n", target.address));
        out.push_str(&format!(
            "MODE: {}\n",
            if self.autonomous {
                "autonomous — drive to finish, never reply"
            } else {
                "interactive — reply ends the turn"
            }
        ));
        out.push_str(&format!(
            "CAPABILITIES ({} available, {} unavailable): {}\n",
            available_capabilities.len(),
            unavailable_count,
            available_capabilities.join(", ")
        ));
        if capability_schemas.is_empty() {
            out.push_str("CAPABILITY SCHEMAS: (none)\n");
        } else {
            out.push_str("CAPABILITY SCHEMAS:\n");
            for s in capability_schemas {
                out.push_str(s);
                out.push('\n');
            }
        }
        out.push_str("VAULT KEYS (names only — use {{vault:key}} references in tool options; values are injected at execution):\n");
        if self.vault_keys.is_empty() {
            out.push_str("(vault empty)\n");
        } else {
            for k in &self.vault_keys {
                out.push_str(k);
                out.push('\n');
            }
        }
        out.push_str("FINDINGS (complete registry — trust over summaries):\n");
        let findings = self.finding_lines();
        if findings.is_empty() {
            out.push_str("(none yet)\n");
        } else {
            for f in &findings {
                out.push_str(f);
                out.push('\n');
            }
        }
        out
    }

    /// Volatile per-step directives, regenerated every call. Sections are
    /// omitted when empty (deterministic). Never cached — this is the one
    /// message allowed to change every step.
    fn build_tail(&self, step: usize) -> String {
        let mut out = format!("STEP: {step}\n");
        if let Some(e) = self.last_error.as_deref().filter(|s| !s.trim().is_empty()) {
            out.push_str(&format!("LAST ERROR (fix this next): {e}\n"));
        }
        if !self.error_history.is_empty() {
            out.push_str("RECENT ERRORS:\n");
            for e in &self.error_history {
                out.push_str(&format!("- {e}\n"));
            }
        }
        if step >= self.staged_note_step {
            if let Some(note) = self
                .staged_model_note
                .as_deref()
                .filter(|s| !s.trim().is_empty())
            {
                out.push_str(&format!("MODEL NOTE: {note}\n"));
            }
        }
        if self.compacted {
            out.push_str(&format!(
                "CONTEXT: conversation compacted {} time(s); older turns are summarized in the first message. The findings registry in the brief is complete — trust it over the summary.\n",
                self.compaction_count
            ));
        }
        if let Some(note) = self.pending_narration_note() {
            out.push_str(&format!("DIRECTIVE (pending_narration): {note}\n"));
        }
        if let Some(hint) = self.strategy_hint() {
            out.push_str(&format!("STRATEGY: {hint}\n"));
        }
        out
    }

    /// Build the budgeted view for one model call.
    ///
    /// Essentials (target, step, capabilities, last error) are never
    /// elided. The remaining budget splits across raw evidence (the
    /// ground truth), observations (the distillate), and prior actions
    /// (the anti-loop record). Within a category the newest records win
    /// and the selection is presented chronologically with an elision
    /// marker so the model knows older history exists.
    pub fn build_view(
        &self,
        target: &Target,
        step: usize,
        available_capabilities: Vec<String>,
        unavailable_count: usize,
    ) -> (ContextView, BudgetReport) {
        self.build_view_with_schemas(
            target,
            step,
            available_capabilities,
            unavailable_count,
            Vec::new(),
        )
    }

    /// [`build_view`] with the semantic option schemas for available
    /// capabilities, so the model knows which options it may pass.
    pub fn build_view_with_schemas(
        &self,
        target: &Target,
        step: usize,
        available_capabilities: Vec<String>,
        unavailable_count: usize,
        capability_schemas: Vec<String>,
    ) -> (ContextView, BudgetReport) {
        let essentials = target.address.len()
            + step.to_string().len()
            + unavailable_count.to_string().len()
            + available_capabilities
                .iter()
                .map(|c| c.len() + 8)
                .sum::<usize>()
            + capability_schemas
                .iter()
                .map(|s| s.len() + 8)
                .sum::<usize>()
            + self.last_error.as_ref().map_or(0, |e| e.len() + 24)
            + self.error_history.iter().map(|e| e.len() + 8).sum::<usize>()
            + 160; // JSON skeleton, field names, slack

        let remaining = self.budget.max_chars.saturating_sub(essentials);
        let mut report = BudgetReport::default();

        let observations = select_newest(
            self.observations.iter().map(observation_line),
            remaining * 25 / 100,
            &mut report.elided_observations,
        );
        let prior_actions = select_newest(
            self.actions.iter().map(action_line),
            remaining * 25 / 100,
            &mut report.elided_actions,
        );
        // Raw tool output gets the largest share: it is the ground truth
        // the observations merely summarize.
        let recent_evidence = select_newest(
            self.evidence.iter().map(evidence_line),
            remaining * 40 / 100,
            &mut report.elided_evidence,
        );
        // What the user was already told — small but essential for not
        // repeating narrations.
        let narrations = select_newest(
            self.narrations.iter().cloned(),
            remaining * 10 / 100,
            &mut report.elided_narrations,
        );

        let view = ContextView {
            target: target.address.clone(),
            step,
            autonomous: false,
            brief: self.build_brief(
                target,
                &available_capabilities,
                unavailable_count,
                &capability_schemas,
            ),
            transcript: self.transcript.clone(),
            tail: self.build_tail(step),
            conversation: self.recent_conversation(),
            available_capabilities,
            unavailable_count,
            observations,
            recent_evidence,
            narrations,
            prior_actions,
            capability_schemas,
            last_error: self.last_error.clone(),
            recent_errors: self.error_history.clone(),
            findings: self.finding_lines(),
            vault_keys: self.vault_keys.clone(),
            vault_values: self.vault_values.clone(),
            context_note: self.compacted.then(|| {
                format!(
                    "The conversation was compacted {} time(s); older turns are summarized in the first conversation turn. The findings registry above is complete and current — trust it over the summary for what is confirmed.",
                    self.compaction_count
                )
            }),
            // AssessmentState projection fills these after build; the
            // manager itself stays a pure budgeted selector, never the
            // system of record for graph/family/completion state.
            attack_summary: Vec::new(),
            family_progress: Vec::new(),
            unknowns: Vec::new(),
            completion_note: None,
            pending_narration: self.pending_narration_note(),
            strategy_hint: self.strategy_hint(),
        };
        report.total_chars = serde_json::to_string(&view)
            .map(|s| s.len())
            .unwrap_or_default();
        (view, report)
    }
}

/// Schema version for the on-disk [`ContextManager`] snapshot. Bump this
/// when the struct's shape changes in a way old files can't deserialize
/// into; [`load_in`] rejects a mismatch instead of returning a partially
/// (or incorrectly) populated manager.
pub const CONTEXT_SCHEMA_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
struct ContextSnapshot {
    schema_version: u32,
    cm: ContextManager,
}

/// Persist a [`ContextManager`] snapshot for `id` under `dir`. Shares the
/// assessment id and directory convention with
/// [`super::assessment::save_in`] (`assessments_dir()`, same id, sibling
/// file) so the two snapshots that make up a resumable session — the
/// authoritative world model and the model-facing context — stay keyed
/// together.
pub fn save_in(dir: &std::path::Path, id: &str, cm: &ContextManager) -> Result<(), String> {
    if !super::assessment::is_valid_id(id) {
        return Err(format!("invalid context snapshot id: {id}"));
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("create context dir: {e}"))?;
    let snapshot = ContextSnapshot {
        schema_version: CONTEXT_SCHEMA_VERSION,
        cm: cm.clone(),
    };
    let text = serde_json::to_string_pretty(&snapshot).map_err(|e| format!("serialize: {e}"))?;
    std::fs::write(dir.join(format!("{id}.context.json")), text)
        .map_err(|e| format!("write context snapshot: {e}"))?;
    Ok(())
}

/// Load a [`ContextManager`] snapshot for `id` from `dir`. A missing file
/// (never snapshotted — older session, or brand new) or a schema mismatch
/// is `Err`; callers fall back to the session log's record-by-record
/// replay (or a fresh manager) in that case.
pub fn load_in(dir: &std::path::Path, id: &str) -> Result<ContextManager, String> {
    if !super::assessment::is_valid_id(id) {
        return Err(format!("invalid context snapshot id: {id}"));
    }
    let path = dir.join(format!("{id}.context.json"));
    let text = std::fs::read_to_string(&path).map_err(|e| format!("open context snapshot: {e}"))?;
    let snapshot: ContextSnapshot =
        serde_json::from_str(&text).map_err(|e| format!("parse context snapshot: {e}"))?;
    if snapshot.schema_version != CONTEXT_SCHEMA_VERSION {
        return Err("stale context snapshot schema".to_string());
    }
    Ok(snapshot.cm)
}

/// [`save_in`] under the shared assessments directory.
pub fn save(id: &str, cm: &ContextManager) -> Result<(), String> {
    save_in(&super::assessment::assessments_dir(), id, cm)
}

/// [`load_in`] under the shared assessments directory.
pub fn load(id: &str) -> Result<ContextManager, String> {
    load_in(&super::assessment::assessments_dir(), id)
}

fn observation_line(o: &Observation) -> String {
    format!("O{}: {}", o.id, o.summary)
}

fn action_line(a: &ActionRecord) -> String {
    let status = if a.effective { "effective" } else { "INEFFECTIVE" };
    if a.reason.trim().is_empty() {
        format!("{} on {} via {} [{status}]", a.capability, a.target, a.provider)
    } else {
        format!(
            "{} on {} via {} [{status}] — {}",
            a.capability, a.target, a.provider, a.reason
        )
    }
}

/// Ranked-order selection under `budget` chars: keep items in the given
/// order (highest priority first) while they fit; drop the rest with a
/// trailing omission marker.
#[cfg(test)]
fn select_first(items: Vec<String>, budget: usize, elided_out: &mut usize) -> Vec<String> {
    if items.is_empty() {
        return Vec::new();
    }
    let total = items.len();
    let mut out = Vec::new();
    let mut used = 0usize;
    let mut kept_all = true;
    for line in items {
        let cost = line.len() + 8;
        if !out.is_empty() && used + cost > budget {
            kept_all = false;
            break;
        }
        used += cost;
        out.push(line);
    }
    if !kept_all {
        *elided_out = total - out.len();
        out.push(format!(
            "[... {elided_out} lower-priority suggestions omitted ...]"
        ));
    } else {
        *elided_out = 0;
    }
    out
}

/// Newest-wins selection under `budget` chars. The single newest item is
/// always kept (a non-empty category must not vanish silently); older items
/// are kept while they fit. Result is chronological with a leading elision
/// marker when anything was dropped.
fn select_newest<I>(lines: I, budget: usize, elided_out: &mut usize) -> Vec<String>
where
    I: Iterator<Item = String>,
{
    let all: Vec<String> = lines.collect();
    if all.is_empty() {
        return Vec::new();
    }
    let mut kept: Vec<&String> = Vec::new();
    let mut used = 0usize;
    for line in all.iter().rev() {
        let cost = line.len() + 8; // quotes, comma, overhead
        if used + cost > budget && !kept.is_empty() {
            break;
        }
        used += cost;
        kept.push(line);
    }
    *elided_out = all.len() - kept.len();
    kept.reverse(); // chronological
    let mut out = Vec::with_capacity(kept.len() + 1);
    if *elided_out > 0 {
        out.push(format!("[... {elided_out} older elided ...]"));
    }
    out.extend(kept.into_iter().cloned());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target {
        Target::new("10.0.0.1")
    }

    fn caps() -> Vec<String> {
        vec!["network.port_scan".to_string(), "http.probe".to_string()]
    }

    #[test]
    fn evidence_truncates_and_rides_the_view() {
        let mut cm = ContextManager::default();
        // Long output keeps its head (scanners get half the allowance)...
        let long = "FINDING one\n".repeat(1_000); // ~12k chars > 6k scanner cap
        cm.add_evidence("nuclei", "10.0.0.1", &long);
        assert_eq!(cm.evidence.len(), 1);
        assert!(cm.evidence[0].output.contains("FINDING one"));
        assert!(cm.evidence[0].output.contains("[truncated,"));
        // ...empty output is skipped...
        cm.add_evidence("httpx", "10.0.0.1", "   ");
        assert_eq!(cm.evidence.len(), 1);
        // ...and only the newest 10 executions are kept.
        for i in 0..12 {
            cm.add_evidence("httpx", "10.0.0.1", &format!("run {i}"));
        }
        assert_eq!(cm.evidence.len(), 10);
        assert!(cm.evidence[0].output.contains("run 2"));
        assert!(cm.evidence[9].output.contains("run 11"));
        // The evidence reaches the model's view.
        let (view, _) = cm.build_view(&target(), 0, caps(), 0);
        assert!(view
            .recent_evidence
            .iter()
            .any(|e| e.contains("[httpx] 10.0.0.1") && e.contains("run 11")));
        // Payload-verification tools get the full allowance (the whole
        // rendered body), scanners get half.
        cm.add_evidence("medusa-http", "10.0.0.1", &("X".repeat(30_000)));
        assert!(cm.evidence.last().unwrap().output.len() >= 12_000);
        // Web research (fetched source/docs) must also get the FULL cap,
        // not half — the model needs to read it, and the line that matters
        // can sit deep in the extract.
        cm.add_evidence("medusa-research", "https://example.com", &("Y".repeat(30_000)));
        let research = cm.evidence.last().unwrap();
        assert_eq!(research.tool_id, "medusa-research");
        assert!(
            research.output.len() >= 12_000,
            "research must get the full cap, got {}",
            research.output.len()
        );
        // A plain scanner still gets only half.
        cm.add_evidence("nuclei", "10.0.0.1", &("Z".repeat(30_000)));
        assert!(cm.evidence.last().unwrap().output.len() < 12_000);
    }

    #[test]
    fn identical_research_refetch_is_deduped() {
        let mut cm = ContextManager::new();
        let page = "challenge head content".repeat(50);
        cm.add_evidence("medusa-research", "https://x/challenges.yml", &page);
        let n = cm.evidence.len();
        // Re-fetching the same URL with the same (windowed) content adds
        // nothing — it must not pile up another identical entry.
        cm.add_evidence("medusa-research", "https://x/challenges.yml", &page);
        cm.add_evidence("medusa-research", "https://x/challenges.yml", &page);
        assert_eq!(cm.evidence.len(), n, "identical re-fetch must be deduped");
        // A DIFFERENT window of the same URL is new information — kept.
        cm.add_evidence("medusa-research", "https://x/challenges.yml", "a different window");
        assert_eq!(cm.evidence.len(), n + 1);
    }

    #[test]
    fn default_budget_fits_a_full_investigation() {
        let mut cm = ContextManager::new();
        for i in 0..25 {
            cm.add_action(
                i,
                "network.port_scan".into(),
                "nmap".into(),
                "10.0.0.1".into(),
                format!("r{i}"),
                true,
            );
            cm.add_observation(
                "10.0.0.1",
                &format!("port {} open", 1000 + i),
                "network.port_scan",
                i,
            );
        }
        let (view, report) = cm.build_view(&target(), 25, caps(), 9);
        assert_eq!(report.elided_observations, 0);
        assert_eq!(report.elided_actions, 0);
        assert_eq!(view.observations.len(), 25);
        assert_eq!(view.prior_actions.len(), 25);
        assert!(report.total_chars <= TokenBudget::default().max_chars);
    }

    #[test]
    fn tight_budget_keeps_newest_and_marks_elision() {
        let mut cm = ContextManager::with_budget(TokenBudget { max_chars: 1_200 });
        for i in 0..60 {
            cm.add_observation(
                "10.0.0.1",
                &format!("observation number {i} with some detail"),
                "network.port_scan",
                i,
            );
        }
        let (view, report) = cm.build_view(&target(), 30, caps(), 9);
        assert!(report.elided_observations > 0);
        assert!(report.elided_observations < 60);
        // elision marker is the first entry, selection is chronological after it
        assert!(view.observations[0].starts_with("[..."));
        let selected = &view.observations[1..];
        let last = selected.last().unwrap();
        assert!(
            last.contains("observation number 59"),
            "newest must survive: {last}"
        );
        // chronological: numbers ascending
        let nums: Vec<usize> = selected
            .iter()
            .filter_map(|l| l.split(' ').nth_back(1).and_then(|n| n.parse().ok()))
            .collect();
        let mut sorted = nums.clone();
        sorted.sort_unstable();
        assert_eq!(nums, sorted);
        assert_eq!(report.elided_observations + selected.len(), 60);
    }

    #[test]
    fn newest_item_survives_even_with_zero_category_budget() {
        let mut cm = ContextManager::with_budget(TokenBudget { max_chars: 0 });
        cm.add_observation("10.0.0.1", "the only observation", "s", 1);
        let (view, _report) = cm.build_view(&target(), 1, caps(), 0);
        // Essentials plus at least the newest entry per non-empty category.
        assert_eq!(view.observations.len(), 1);
        assert!(view.observations[0].contains("the only observation"));
    }

    #[test]
    fn capabilities_are_never_elided() {
        let cm = ContextManager::with_budget(TokenBudget { max_chars: 0 });
        let many: Vec<String> = (0..61)
            .map(|i| format!("category.capability_{i}"))
            .collect();
        let (view, _) = cm.build_view(&target(), 1, many.clone(), 5);
        assert_eq!(view.available_capabilities, many);
    }

    #[test]
    fn last_error_always_reaches_the_model() {
        let mut cm = ContextManager::with_budget(TokenBudget { max_chars: 0 });
        cm.set_last_error(Some("no provider for cloud.posture_audit".into()));
        let (view, _) = cm.build_view(&target(), 1, caps(), 0);
        assert_eq!(
            view.last_error.as_deref(),
            Some("no provider for cloud.posture_audit")
        );
    }

    #[test]
    fn duplicate_observation_summaries_collapse() {
        let mut cm = ContextManager::new();
        let a = cm.add_observation("10.0.0.1", "port 22 open", "network.port_scan", 1);
        let b = cm.add_observation("10.0.0.1", "port 22 open", "network.port_scan", 4);
        assert_eq!(a, b, "duplicate must return the original id");
        assert_eq!(cm.observations().len(), 1);
        let (view, _) = cm.build_view(&target(), 5, caps(), 0);
        assert_eq!(view.observations.len(), 1);
    }

    #[test]
    fn action_lines_carry_target_and_provider() {
        let mut cm = ContextManager::new();
        cm.add_action(
            2,
            "network.port_scan".into(),
            "nmap".into(),
            "10.0.0.9".into(),
            "unknown services".into(),
            true,
        );
        let (view, _) = cm.build_view(&target(), 3, caps(), 0);
        assert_eq!(
            view.prior_actions,
            vec!["network.port_scan on 10.0.0.9 via nmap [effective] — unknown services".to_string()]
        );
    }

    #[test]
    fn action_lines_flag_ineffective_runs() {
        let mut cm = ContextManager::new();
        cm.add_action(
            1,
            "web.sql_injection".into(),
            "sqlmap".into(),
            "http://x/login".into(),
            "test login form for SQLi".into(),
            false,
        );
        let (view, _) = cm.build_view(&target(), 2, caps(), 0);
        assert_eq!(
            view.prior_actions,
            vec![
                "web.sql_injection on http://x/login via sqlmap [INEFFECTIVE] — test login form for SQLi"
                    .to_string()
            ]
        );
    }

    #[test]
    fn error_history_accumulates_distinct_errors_and_never_clears() {
        let mut cm = ContextManager::new();
        cm.set_last_error(Some("first failure: connection refused".into()));
        cm.set_last_error(None);
        cm.set_last_error(Some("second failure: 403 forbidden".into()));
        let (view, _) = cm.build_view(&target(), 2, caps(), 0);
        assert_eq!(view.last_error.as_deref(), Some("second failure: 403 forbidden"));
        assert_eq!(
            view.recent_errors,
            vec![
                "first failure: connection refused".to_string(),
                "second failure: 403 forbidden".to_string(),
            ]
        );
    }

    #[test]
    fn error_history_dedupes_immediate_repeats_and_is_bounded() {
        let mut cm = ContextManager::new();
        for i in 0..10 {
            cm.set_last_error(Some(format!("error {i}")));
        }
        cm.set_last_error(Some("error 9".into()));
        let (view, _) = cm.build_view(&target(), 10, caps(), 0);
        assert!(view.recent_errors.len() <= 6, "must stay bounded: {:?}", view.recent_errors);
        assert_eq!(view.recent_errors.last().unwrap(), "error 9");
    }

    #[test]
    fn ids_are_stable_and_sequential() {
        let mut cm = ContextManager::new();
        assert_eq!(cm.add_observation("t", "a", "s", 0), 1);
        assert_eq!(cm.add_observation("t", "b", "s", 0), 2);
    }

    #[test]
    fn findings_dedupe_and_update() {
        let mut cm = ContextManager::new();
        let a = cm.add_finding("High", "SQLi in login", "10.0.0.1", "web.scan", "error-based", 3);
        assert_eq!(a, 1);
        // Same title+target re-report updates instead of duplicating.
        let b = cm.add_finding("Critical", "SQLi in login", "10.0.0.1", "web.scan", "confirmed blind", 5);
        assert_eq!(b, 1);
        assert_eq!(cm.findings().len(), 1);
        assert_eq!(cm.findings()[0].severity, "Critical");
        assert_eq!(cm.findings()[0].step_updated, 5);
        // Status transitions work; unknown ids fail loudly.
        assert!(cm.update_finding(1, "confirmed", 6));
        assert_eq!(cm.findings()[0].status, "confirmed");
        assert!(!cm.update_finding(99, "confirmed", 6));
        // The full registry rides the view even on a zero budget.
        let starved = ContextManager::with_budget(TokenBudget { max_chars: 0 });
        let mut starved = starved;
        starved.add_finding("Low", "banner", "10.0.0.1", "s", "", 1);
        let (view, _) = starved.build_view(&target(), 1, caps(), 0);
        assert_eq!(view.findings.len(), 1);
        assert!(view.findings[0].contains("F1"));
        assert!(view.context_note.is_none());
    }

    #[test]
    fn pending_narration_fires_on_new_finding_and_clears_on_narrate() {
        let mut cm = ContextManager::new();
        // Nothing found yet: no nudge.
        let (view, _) = cm.build_view(&target(), 1, caps(), 0);
        assert!(view.pending_narration.is_none());

        // A finding is recorded but not announced: the harness demands it.
        cm.add_finding("High", "SQLi in login", "10.0.0.1", "web.scan", "error-based", 2);
        let (view, _) = cm.build_view(&target(), 3, caps(), 0);
        let note = view.pending_narration.expect("must nudge for unnarrated finding");
        assert!(note.contains("F1"));
        assert!(note.contains("SQLi in login"));

        // The model narrates: the backlog clears.
        cm.add_narration("Confirmed SQL injection in the login form.");
        let (view, _) = cm.build_view(&target(), 4, caps(), 0);
        assert!(
            view.pending_narration.is_none(),
            "narrating must clear the pending-narration nudge"
        );

        // A second, later finding re-arms the nudge for that one only.
        cm.add_finding("Critical", "RCE via upload", "10.0.0.1", "web.scan", "shell", 5);
        let (view, _) = cm.build_view(&target(), 6, caps(), 0);
        let note = view.pending_narration.expect("new finding must re-arm the nudge");
        assert!(note.contains("RCE via upload"));
        assert!(!note.contains("SQLi in login"), "already-narrated finding must not reappear");
    }

    #[test]
    fn strategy_hint_fires_after_actions_without_a_finding_and_resets_on_one() {
        let mut cm = ContextManager::new();
        // A few actions, no finding yet: below threshold, no hint.
        for i in 0..4 {
            cm.add_action(i, "http.request".into(), "medusa-http".into(), "t".into(), "probe".into(), true);
        }
        let (view, _) = cm.build_view(&target(), 4, caps(), 0);
        assert!(view.strategy_hint.is_none());

        // Cross the threshold with no finding: the harness warns of thrashing.
        for i in 4..9 {
            cm.add_action(i, "http.request".into(), "medusa-http".into(), "t".into(), "probe".into(), true);
        }
        let (view, _) = cm.build_view(&target(), 9, caps(), 0);
        let hint = view.strategy_hint.expect("stall must raise a strategy hint");
        assert!(hint.contains("web.research"), "hint should point at reading source: {hint}");

        // A new finding resets the counter — progress clears the hint.
        cm.add_finding("High", "open redirect", "t", "http.request", "d", 9);
        let (view, _) = cm.build_view(&target(), 10, caps(), 0);
        assert!(
            view.strategy_hint.is_none(),
            "a new finding must clear the thrashing hint"
        );
    }

    #[test]
    fn replay_finding_restores_ids_without_dupes() {
        let mut cm = ContextManager::new();
        cm.replay_finding(Finding {
            id: 2,
            severity: "High".into(),
            title: "RCE".into(),
            target: "10.0.0.1".into(),
            source: "s".into(),
            detail: "d".into(),
            status: "confirmed".into(),
            step_found: 4,
            step_updated: 7,
        });
        cm.replay_finding(Finding {
            id: 2,
            severity: "High".into(),
            title: "RCE".into(),
            target: "10.0.0.1".into(),
            source: "s".into(),
            detail: "d".into(),
            status: "confirmed".into(),
            step_found: 4,
            step_updated: 7,
        });
        assert_eq!(cm.findings().len(), 1);
        assert_eq!(cm.findings()[0].status, "confirmed");
    }

    #[test]
    fn compact_keeps_findings_vault_and_tail() {
        let mut cm = ContextManager::new();
        for i in 0..6 {
            cm.begin_turn(&format!("user {i}"));
            cm.end_turn(&format!("assistant {i}"));
            cm.add_observation("10.0.0.1", &format!("obs {i}"), "s", i);
            cm.add_evidence("nmap", "10.0.0.1", &format!("raw {i}"));
        }
        cm.add_finding("High", "SQLi", "10.0.0.1", "web.scan", "d", 5);
        cm.set_vault_keys(vec!["db_password [password]".into()]);
        cm.add_narration("told the user about SQLi");
        cm.compact("summary of six turns", 2);
        // Summary turn + last two verbatim turns.
        assert_eq!(cm.conversation.len(), 3);
        assert!(cm.conversation[0].assistant.contains("summary of six turns"));
        assert_eq!(cm.conversation[1].user, "user 4");
        // Evidence dropped, findings/vault/narrations intact.
        assert!(cm.evidence.is_empty());
        assert_eq!(cm.findings().len(), 1);
        assert_eq!(cm.vault_keys.len(), 1);
        assert!(cm.was_compacted());
        assert_eq!(cm.compaction_count, 1);
        let (view, _) = cm.build_view(&target(), 6, caps(), 0);
        assert_eq!(view.findings.len(), 1);
        assert!(view.context_note.is_some());
        assert_eq!(view.vault_keys.len(), 1);
        assert_eq!(view.narrations.len(), 1);
    }

    #[test]
    fn transcript_records_turns_and_steps_append_only() {
        let mut cm = ContextManager::new();
        cm.begin_turn("assess 10.0.0.1");
        cm.add_observation("10.0.0.1", "port 80 open", "nmap", 0);
        cm.add_evidence("nmap", "10.0.0.1", "PORT 80/tcp open");
        cm.push_assistant("{\"decision\":\"execute\"}".into());
        cm.add_narration("found a web server");
        let roles: Vec<&str> = cm
            .transcript()
            .iter()
            .map(|m| m.role.as_str())
            .collect();
        assert_eq!(roles, vec!["user", "user", "user", "assistant", "assistant"]);
        assert_eq!(cm.transcript()[0].content, "assess 10.0.0.1");
        // Empty pushes are ignored — no blank messages on the wire.
        cm.push_user("   ".into());
        cm.push_assistant(String::new());
        assert_eq!(cm.transcript().len(), 5);
        // Later views extend the transcript; earlier messages never change.
        let (v1, _) = cm.build_view(&target(), 1, caps(), 0);
        cm.add_observation("10.0.0.1", "port 443 open", "nmap", 1);
        let (v2, _) = cm.build_view(&target(), 2, caps(), 0);
        assert!(v2.transcript.starts_with(&v1.transcript));
        assert_eq!(v2.transcript.len(), v1.transcript.len() + 1);
    }

    #[test]
    fn transcript_dedups_repeated_observations() {
        let mut cm = ContextManager::new();
        cm.add_observation("t", "same summary", "s", 0);
        cm.add_observation("t", "same summary", "s", 1);
        assert_eq!(cm.transcript().len(), 1);
        // Empty evidence is skipped everywhere, transcript included.
        cm.add_evidence("nmap", "t", "");
        assert_eq!(cm.transcript().len(), 1);
    }

    #[test]
    fn staged_model_note_hidden_same_step_shown_next() {
        let mut cm = ContextManager::new();
        cm.begin_turn("go");
        cm.stage_model_note("model call failed (boom) — retried 1/5".into(), 3);
        // Same-step retry rebuild: no note → byte-identical request.
        let (retry_view, _) = cm.build_view(&target(), 3, caps(), 0);
        assert!(
            !retry_view.tail.contains("MODEL NOTE"),
            "tail was: {}",
            retry_view.tail
        );
        // Next step: the note surfaces in the tail.
        let (next_view, _) = cm.build_view(&target(), 4, caps(), 0);
        assert!(
            next_view.tail.contains("MODEL NOTE: model call failed (boom)"),
            "tail was: {}",
            next_view.tail
        );
        // Clearing drops it again.
        cm.clear_staged_model_note();
        let (cleared, _) = cm.build_view(&target(), 5, caps(), 0);
        assert!(!cleared.tail.contains("MODEL NOTE"));
    }

    #[test]
    fn compact_rewrites_transcript_boundary() {
        let mut cm = ContextManager::new();
        for i in 0..4 {
            cm.begin_turn(&format!("user {i}"));
            cm.push_assistant(format!("{{\"decision\":\"finish\",\"reason\":\"{i}\"}}"));
            cm.add_observation("t", &format!("obs {i}"), "s", i);
        }
        cm.stage_model_note("stale note".into(), 3);
        cm.compact("summary of four turns", 2);
        // Summary exchange first, then the most recent messages verbatim.
        assert_eq!(cm.transcript()[0].role, "user");
        assert_eq!(cm.transcript()[1].content, "summary of four turns");
        assert!(cm.transcript().len() > 2);
        // A staged note must not survive the boundary.
        let (view, _) = cm.build_view(&target(), 4, caps(), 0);
        assert!(!view.tail.contains("stale note"), "tail was: {}", view.tail);
        assert!(view.tail.contains("STEP: 4"));
    }

    #[test]
    fn transcript_survives_snapshot_round_trip() {
        let mut cm = ContextManager::new();
        cm.begin_turn("assess 10.0.0.1");
        cm.add_observation("10.0.0.1", "port 80 open", "nmap", 0);
        cm.push_assistant("{\"decision\":\"finish\"}".into());
        let dir = std::env::temp_dir().join(format!(
            "medusa-transcript-rt-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        save_in(&dir, "testsession1", &cm).unwrap();
        let loaded = load_in(&dir, "testsession1").unwrap();
        assert_eq!(loaded.transcript(), cm.transcript());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn brief_head_stable_when_findings_grow() {
        let mut cm = ContextManager::new();
        cm.set_vault_keys(vec!["db_password [password]".into()]);
        let (v1, _) = cm.build_view(&target(), 0, caps(), 0);
        cm.add_finding("High", "SQLi", "10.0.0.1", "web.scan", "detail", 1);
        let (v2, _) = cm.build_view(&target(), 1, caps(), 0);
        // Everything before the findings section is byte-identical: a new
        // finding only extends the brief's end (cache-safe growth).
        let head_end = |b: &str| b.find("FINDINGS").unwrap_or(b.len());
        assert_eq!(&v1.brief[..head_end(&v1.brief)], &v2.brief[..head_end(&v2.brief)]);
        assert!(v2.brief.contains("SQLi"));
        // The tail always carries the step (volatile by design).
        assert!(v1.tail.contains("STEP: 0"));
        assert!(v2.tail.contains("STEP: 1"));
    }

    #[test]
    fn vault_values_ride_one_view() {
        let mut cm = ContextManager::new();
        cm.recall_vault_value("db_password", "s3cr3t");
        let (view, _) = cm.build_view(&target(), 0, caps(), 0);
        assert_eq!(view.vault_values, vec!["db_password=s3cr3t".to_string()]);
        cm.clear_vault_values();
        let (view, _) = cm.build_view(&target(), 0, caps(), 0);
        assert!(view.vault_values.is_empty());
    }

    fn snapshot_temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("medusa-context-snapshot-test-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn snapshot_round_trips_actions_evidence_and_errors() {
        let dir = snapshot_temp_dir("roundtrip");
        let mut cm = ContextManager::new();
        cm.add_action(
            1,
            "network.port_scan".into(),
            "nmap".into(),
            "10.0.0.1".into(),
            "map services".into(),
            true,
        );
        cm.add_evidence("nmap", "10.0.0.1", "22/tcp open ssh");
        cm.set_last_error(Some("connection refused".into()));
        cm.set_last_error(None);
        cm.add_finding("High", "SQLi", "10.0.0.1", "web.scan", "d", 1);
        cm.add_narration("told the user about SQLi");
        cm.begin_turn("scan it");
        cm.end_turn("working on it");
        save_in(&dir, "a1", &cm).unwrap();
        let restored = load_in(&dir, "a1").unwrap();
        let (view, _) = restored.build_view(&target(), 2, caps(), 0);
        assert_eq!(view.prior_actions.len(), 1);
        assert!(view.prior_actions[0].contains("[effective]"));
        assert_eq!(view.recent_evidence.len(), 1);
        assert_eq!(view.recent_errors, vec!["connection refused".to_string()]);
        assert_eq!(view.findings.len(), 1);
        assert_eq!(view.narrations.len(), 1);
        assert_eq!(view.conversation.len(), 1);
        assert!(view.conversation[0].assistant.contains("working on it"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn snapshot_never_persists_vault_values() {
        let dir = snapshot_temp_dir("vault");
        let mut cm = ContextManager::new();
        cm.set_vault_keys(vec!["db_password [password]".into()]);
        cm.recall_vault_value("db_password", "s3cr3t-value");
        save_in(&dir, "a2", &cm).unwrap();
        let text = std::fs::read_to_string(dir.join("a2.context.json")).unwrap();
        assert!(!text.contains("s3cr3t-value"), "vault value leaked into snapshot: {text}");
        let restored = load_in(&dir, "a2").unwrap();
        let (view, _) = restored.build_view(&target(), 0, caps(), 0);
        assert!(view.vault_keys.is_empty());
        assert!(view.vault_values.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn snapshot_load_rejects_missing_and_invalid_ids() {
        let dir = snapshot_temp_dir("missing");
        assert!(load_in(&dir, "never-saved").is_err());
        assert!(load_in(&dir, "../evil").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
