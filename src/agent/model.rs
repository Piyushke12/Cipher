//! Model abstraction: the LLM decides *what capability it needs*, never
//! *how* it is fulfilled. Decisions are structured (`Decision`), so the
//! runtime — not the model — resolves capabilities to providers, enforces
//! policy, and constructs tool invocations.

use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::agent::executor::{LocalProcessExecutor, ProcessExecutor};

/// One semantic option value supplied by the model. Scalars plus
/// string maps (for structured options like HTTP headers); arrays and
/// nested objects are rejected at the wire boundary, and the value must
/// satisfy the capability's option schema before anything runs.
#[derive(Debug, Clone, PartialEq)]
pub enum OptionValue {
    Str(String),
    Num(f64),
    Bool(bool),
    /// String-to-string map, e.g. `headers: {"Authorization": "Bearer x"}`.
    /// Keys and values are validated by the option schema (see
    /// `OptionKind::Map`); values are never rendered into shell argv.
    Map(std::collections::BTreeMap<String, String>),
}

impl std::fmt::Display for OptionValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Str(s) => write!(f, "{s}"),
            Self::Num(n) => write!(f, "{n}"),
            Self::Bool(b) => write!(f, "{b}"),
            // Names only — values may carry tokens and must never leak
            // into evidence strings, feedback, or logs.
            Self::Map(m) => {
                let names: Vec<&str> = m.keys().map(|k| k.as_str()).collect();
                write!(f, "{{{}}}", names.join(", "))
            }
        }
    }
}

impl OptionValue {
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::Str(_) => "a string",
            Self::Num(_) => "a number",
            Self::Bool(_) => "a boolean",
            Self::Map(_) => "an object of string pairs",
        }
    }

    /// Render for a provider flag (trusted translation step).
    pub fn render(&self) -> String {
        match self {
            Self::Str(s) => s.clone(),
            Self::Num(n) => {
                if n.fract() == 0.0 && n.abs() < 1e15 {
                    format!("{}", *n as i64)
                } else {
                    format!("{n}")
                }
            }
            Self::Bool(b) => b.to_string(),
            // Structured values have no flag rendering; providers that
            // bind them consume the map directly (see http provider).
            Self::Map(m) => {
                let names: Vec<&str> = m.keys().map(|k| k.as_str()).collect();
                format!("{{{}}}", names.join(", "))
            }
        }
    }
}

/// Validated-ish semantic options keyed by name. Keys/values are checked
/// against the capability's `OptionSpec` schema by the ExecutionPolicy
/// before provider selection.
pub type OptionSet = BTreeMap<String, OptionValue>;

/// One append-only transcript message: the wire format of the
/// conversation. Pushed at recording time, never rewritten (except the
/// compaction-boundary rewrite), so step N+1's message array always starts
/// with step N's array verbatim — the prefix property every production KV
/// cache (Anthropic breakpoints, OpenAI implicit caching, vLLM block
/// hashing, SGLang radix trees) keys on. Persisted with the
/// ContextManager snapshot, so resume restores byte-identical history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptMsg {
    /// "user" or "assistant" (anything else normalizes to "user" at render).
    pub role: String,
    /// Message text. Never carries vault values (see `{{vault:key}}`
    /// references) or other ephemeral secrets.
    pub content: String,
}

impl TranscriptMsg {
    pub fn user(content: String) -> Self {
        Self {
            role: "user".to_string(),
            content,
        }
    }

    pub fn assistant(content: String) -> Self {
        Self {
            role: "assistant".to_string(),
            content,
        }
    }
}

/// Minimal context snapshot handed to the model. Built by the Phase 2
/// [`crate::agent::context::ContextManager`] — budgeted, recency-filtered,
/// deduplicated; the trait boundary stays the same.
///
/// Wire shape (cache-first): providers render `[system] + [brief] +
/// [transcript...] + [tail]`, NOT the legacy fields below as one JSON
/// blob. `brief` is session-stable with append-only growth at its end,
/// `transcript` is strictly append-only between compactions, and `tail`
/// is regenerated every step. The legacy budgeted fields are still
/// populated (tests, compaction materials, budget accounting) but no
/// longer travel the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ContextView {
    /// Stable engagement context: target, mode, capabilities, schemas,
    /// vault key names, findings registry. Byte-stable head; only the
    /// findings section at its end grows (append-only).
    #[serde(default)]
    pub brief: String,
    /// Append-only conversation + step messages, oldest first.
    #[serde(default)]
    pub transcript: Vec<TranscriptMsg>,
    /// Volatile per-step directives: step counter, errors, staged notes,
    /// state projections, hints. Regenerated every call; never cached.
    #[serde(default)]
    pub tail: String,
    pub target: String,
    pub step: usize,
    /// True in autonomous assessment mode (CLI `assess`): the model must
    /// drive to `finish` and never use `reply`. False in interactive
    /// sessions, where `reply` ends the turn with an answer for the user.
    pub autonomous: bool,
    /// Full conversation history (unbounded). The model sees what the
    /// user said and what it answered, verbatim.
    pub conversation: Vec<ChatTurn>,
    pub available_capabilities: Vec<String>,
    pub unavailable_count: usize,
    /// Selected observations (newest-first selection, chronological
    /// presentation). Empty until parsers feed the ContextManager (Phase 5).
    pub observations: Vec<String>,
    /// Updates you ALREADY sent to the user (narrations and replies).
    /// Never re-announce something on this list — mention only what is
    /// new since your last update.
    pub narrations: Vec<String>,
    /// Raw (truncated) output of recent tool executions — the undistilled
    /// evidence behind the summarized observations. Format:
    /// "[tool_id] target:\n<head of raw output>".
    pub recent_evidence: Vec<String>,
    pub prior_actions: Vec<String>,
    pub capability_schemas: Vec<String>,
    pub last_error: Option<String>,
    #[serde(default)]
    pub recent_errors: Vec<String>,
    /// The session findings registry, verbatim and NEVER elided (see
    /// `ContextManager::finding_lines`). Findings are small and
    /// high-value: they survive budgeting and compaction so the model
    /// never loses track of confirmed vulnerabilities.
    #[serde(default)]
    pub findings: Vec<String>,
    /// Vault KEY NAMES only — never values. The model recalls a value
    /// with the `vault_recall` decision exactly when it needs it.
    #[serde(default)]
    pub vault_keys: Vec<String>,
    /// Recalled vault values for THIS decision only (`key=value` lines).
    /// Populated by a `vault_recall` on the previous step; the runtime
    /// clears them after one decision (least exposure).
    #[serde(default)]
    pub vault_values: Vec<String>,
    /// Set after a compaction: tells the model older turns were
    /// summarized and where the summary lives (first conversation turn).
    #[serde(default)]
    pub context_note: Option<String>,
    /// Compact attack-state projection (privileges, paths, newly opened
    /// surfaces). Built from AssessmentState; never a full graph dump.
    #[serde(default)]
    pub attack_summary: Vec<String>,
    /// Per-family progress lines (`family: status tested/total`).
    #[serde(default)]
    pub family_progress: Vec<String>,
    /// High-value unresolved questions (structured objectives).
    #[serde(default)]
    pub unknowns: Vec<String>,
    /// Completion status hint (`allowed` or remaining count).
    #[serde(default)]
    pub completion_note: Option<String>,
    /// Harness directive set when findings were recorded but not yet
    /// narrated to the user: names them and asks for a `narrate` before
    /// the next action. Keeps the agent conversational about wins
    /// instead of silently moving to the next tool. `None` when the user
    /// is already current.
    #[serde(default)]
    pub pending_narration: Option<String>,
    /// Harness directive set when many actions have passed with no new
    /// finding — the signature of thrashing on one approach. Tells the
    /// model to stop permuting and change strategy (read source, switch
    /// vector). `None` while the agent is still making progress.
    #[serde(default)]
    pub strategy_hint: Option<String>,
}

/// One conversational exchange shown in the context. `assistant` is the
/// reply text that ended the turn (empty if the turn ended otherwise).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatTurn {
    pub user: String,
    pub assistant: String,
}

/// What the model may ask for. `Reply` ends the current turn with a
/// conversational answer; `Execute` continues the agentic loop.
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    Execute {
        capability: String,
        target: String,
        /// Semantic options for the capability (validated against its
        /// schema by policy). The model cannot name providers, binaries,
        /// flags, or commands.
        options: OptionSet,
        reason: String,
    },
    CreateHypothesis {
        statement: String,
        confidence: String,
    },
    Finish {
        reason: String,
    },
    /// Conversational answer to the user. Terminates the turn; the session
    /// (context, world model, conversation) persists across turns.
    Reply {
        text: String,
    },
    /// Mid-turn verbal update to the user — what was found, validated, or
    /// changed in understanding. Does NOT end the turn: the loop keeps
    /// working after narrating. Rendered as a normal agent message, not
    /// as thinking.
    Narrate {
        text: String,
    },
    /// Direct web-search tool (NOT a capability — no policy/provider
    /// machinery). The model searches the public web for research:
    /// CVE lookups, documentation, error messages, background.
    WebSearch {
        query: String,
        reason: String,
    },
    /// Direct file tool (NOT a capability). Read a file the target has
    /// dropped: package manifests, config, source, bundle.js. Confined:
    /// only readable/writable paths (see `agent::file_tools`); out-of-scope
    /// reads are refused. The session scope is the assessment root.
    ///
    /// By default reads are distilled (default 40 lines, centered around
    /// any `grep` hits) rather than dumped wholesale into context, so a
    /// large file does not blow the budget. `lines` overrides the window;
    /// `grep` returns only matching lines (with context).
    FileRead {
        path: String,
        /// Grep pattern — when set, only matching lines (+ context) are
        /// returned. Optional.
        grep: Option<String>,
        /// Number of lines to return (default 40). Optional bounded cap.
        lines: Option<u32>,
        reason: String,
    },
    /// Direct file tool. Write a proof-of-concept/exploit to an in-scope
    /// directory (see `agent::file_tools` for confinement + promotion).
    FileWrite {
        path: String,
        content: String,
        reason: String,
    },
    /// Record a security finding in the session registry (persists
    /// across compaction and reloads). This is how findings are
    /// TRACKED; `narrate` is how they are ANNOUNCED.
    ReportFinding {
        severity: String,
        title: String,
        target: String,
        detail: String,
    },
    /// Change a registry finding's status (`open`/`confirmed`/
    /// `false_positive`) when validation confirms or refutes it.
    UpdateFinding {
        id: usize,
        status: String,
        note: String,
    },
    /// Store a NON-EXPIRING secret in the per-target vault (passwords,
    /// signing secrets, S2S keys, env values). Expiring credentials
    /// (bearer/session/JWT tokens) are rejected by the runtime.
    VaultStore {
        key: String,
        value: String,
        kind: String,
        source: String,
    },
    /// Recall a vault value for immediate use. Visible for ONE decision
    /// only, then dropped — recall again if still needed later.
    VaultRecall {
        query: String,
    },
}

/// Token usage for one model call, from the provider's `usage` block
/// when it reports one (OpenAI-compatible `prompt_tokens` /
/// `completion_tokens` / `total_tokens`) or a char/4 estimate otherwise.
/// The drive loop tracks the latest total against the model's context
/// window to drive the context meter and auto-compaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UsageReport {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    /// Tokens served from the provider's prefix cache (`usage.
    /// prompt_tokens_details.cached_tokens`), 0 when unreported. Drives
    /// the cache hit-rate telemetry — the operational signal the whole
    /// context architecture optimizes for.
    pub cached_tokens: u64,
    /// True when no `usage` block was reported and the numbers are a
    /// char/4 heuristic over the serialized prompt.
    pub estimated: bool,
}

impl UsageReport {
    pub fn estimate(prompt_chars: usize, completion_chars: usize) -> Self {
        let prompt = (prompt_chars / 4) as u64;
        let completion = (completion_chars / 4) as u64;
        Self {
            prompt_tokens: prompt,
            completion_tokens: completion,
            total_tokens: prompt + completion,
            cached_tokens: 0,
            estimated: true,
        }
    }

    /// Share of input tokens served from cache, if the endpoint reports
    /// both numbers. `None` when usage is estimated or unreported.
    pub fn cache_hit_rate(&self) -> Option<f64> {
        if self.estimated || self.prompt_tokens == 0 {
            return None;
        }
        Some(self.cached_tokens.min(self.prompt_tokens) as f64 / self.prompt_tokens as f64)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelError {
    Transport(String),
    BadResponse(String),
    MissingConfig(String),
    /// The user pressed Stop (or the runtime is shutting down) while the
    /// call was in flight. NOT a failure: no retry, no error count — the
    /// drive loop turns it into `DriveOutcome::Cancelled` directly.
    Cancelled,
}

impl std::fmt::Display for ModelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "model transport error: {e}"),
            Self::BadResponse(e) => write!(f, "model returned unusable decision: {e}"),
            Self::MissingConfig(e) => write!(f, "model misconfigured: {e}"),
            Self::Cancelled => write!(f, "model call cancelled"),
        }
    }
}

/// Anything that can turn a [`ContextView`] into a [`Decision`].
/// Sync by design in Phase 1; async arrives with tool execution (Phase 4).
/// `Send` so investigations can run on a worker thread under the TUI.
pub trait ModelProvider: Send {
    fn name(&self) -> &str;
    /// One investigation step: structured decision, never free shell.
    fn decide(&self, ctx: &ContextView) -> Result<Decision, ModelError>;
    /// [`decide`] plus the call's token usage. Defaults to a char/4
    /// estimate over the serialized view; providers whose endpoint
    /// reports `usage` override this with real numbers.
    fn decide_reported(&self, ctx: &ContextView) -> (Result<Decision, ModelError>, UsageReport) {
        let chars = serde_json::to_string(ctx).map(|s| s.len()).unwrap_or(0);
        let outcome = self.decide(ctx);
        (outcome, UsageReport::estimate(chars, 0))
    }
    /// One conversational turn: free-text reply (chat UI, routing, summaries).
    /// Plain text, no JSON contract — callers that need structure parse it.
    fn chat(&self, system: &str, user: &str) -> Result<String, ModelError>;

    /// Share the session's cancel flag so a provider that shells out (the
    /// CLI harness) can kill its in-flight model subprocess when the user
    /// presses Stop, instead of blocking the turn until the call finishes.
    /// Default no-op: HTTP and stub providers have nothing to kill. The
    /// runtime calls this when a handle is attached and on model swap.
    fn set_cancel_flag(&mut self, _flag: Arc<AtomicBool>) {}

    /// Multi-message chat for transcript-aware calls (compaction fork).
    /// Default joins the messages into one user text and delegates to
    /// [`Self::chat`]; JSON providers override with a native array so the
    /// fork shares the parent's exact prefix (cache hit).
    fn chat_messages(&self, system: &str, messages: &[serde_json::Value]) -> Result<String, ModelError> {
        let joined = messages
            .iter()
            .filter_map(|m| {
                let role = m.get("role").and_then(|r| r.as_str()).unwrap_or("user");
                let content = m.get("content").and_then(|c| c.as_str()).unwrap_or("");
                if content.trim().is_empty() {
                    None
                } else {
                    Some(format!("{role}: {content}"))
                }
            })
            .collect::<Vec<_>>()
            .join("\n\n");
        self.chat(system, &joined)
    }

    /// Pin a stable per-session routing key (cache affinity where the
    /// gateway honors it; harmless elsewhere). Default no-op; the
    /// OpenAI-compatible provider sends it as `X-Cipher-Session`.
    fn set_session_key(&mut self, _key: String) {}
}

/// Render the cache-first wire format: `[brief] + [transcript...] +
/// [tail]` as a messages array (system is prepended by the caller).
/// Deterministic: fixed section order, blank sections dropped, unknown
/// roles normalize to "user". Step N+1's array always starts with step
/// N's array verbatim as long as callers only append — the prefix
/// property every production KV cache keys on.
pub fn render_chat_messages(
    brief: &str,
    transcript: &[TranscriptMsg],
    tail: &str,
) -> Vec<serde_json::Value> {
    let mut messages = Vec::new();
    if !brief.trim().is_empty() {
        messages.push(serde_json::json!({"role": "user", "content": brief}));
    }
    for m in transcript {
        if m.content.trim().is_empty() {
            continue;
        }
        let role = if m.role == "assistant" {
            "assistant"
        } else {
            "user"
        };
        messages.push(serde_json::json!({"role": role, "content": m.content}));
    }
    if !tail.trim().is_empty() {
        messages.push(serde_json::json!({"role": "user", "content": tail}));
    }
    messages
}

/// Same transcript contract as [`render_chat_messages`], flattened for a
/// local harness's single stdin/argv string: system, then the stable
/// brief, then the transcript with explicit role prefixes (oldest first),
/// then the volatile tail. Deterministic — the same transcript always
/// renders the same prompt.
pub fn render_cli_prompt(
    system: &str,
    brief: &str,
    transcript: &[TranscriptMsg],
    tail: &str,
) -> String {
    let mut parts = vec![system.to_string()];
    if !brief.trim().is_empty() {
        parts.push(brief.to_string());
    }
    for m in transcript {
        if m.content.trim().is_empty() {
            continue;
        }
        let role = if m.role == "assistant" {
            "Assistant"
        } else {
            "User"
        };
        parts.push(format!("{role}: {}", m.content));
    }
    if !tail.trim().is_empty() {
        parts.push(tail.to_string());
    }
    parts.join("\n\n---\n\n")
}

/// Diagnostic for an unparseable model reply: length plus brace counts
/// — enough to distinguish the three failure modes (empty/prose-only
/// reply vs truncated JSON vs present-but-invalid JSON) WITHOUT keeping
/// any reply content. Content is deliberately excluded: a failed reply
/// can carry model-authored secrets (e.g. a `vault_store` value), which
/// must never enter Status messages, traces, or session files.
pub fn describe_unparseable_reply(content: &str) -> String {
    let len = content.chars().count();
    let opens = content.chars().filter(|&c| c == '{').count();
    let closes = content.chars().filter(|&c| c == '}').count();
    format!("{len} chars, {opens} '{{', {closes} '}}'")
}

/// Enrich a parse failure with [`describe_unparseable_reply`]. Parse
/// successes pass through untouched.
fn with_reply_diagnostics(
    result: Result<Decision, ModelError>,
    content: &str,
) -> Result<Decision, ModelError> {
    match result {
        Err(ModelError::BadResponse(kind)) => Err(ModelError::BadResponse(format!(
            "{kind} [reply: {}]",
            describe_unparseable_reply(content)
        ))),
        other => other,
    }
}

/// Deterministic rendering of a decision for assistant replay in the
/// transcript. `reply`/`narrate` replay as their natural text; structured
/// decisions replay as compact JSON. Secrets never ride along:
/// `vault_store` keeps key+kind only (the value lives in the vault
/// file), and `execute`/`file_write` omit options/content — mirroring
/// `prior_actions`, which never carried them — so a pasted credential
/// can't leak into history either.
pub fn render_decision_for_transcript(d: &Decision) -> String {
    match d {
        Decision::Reply { text } | Decision::Narrate { text } => text.clone(),
        Decision::Execute {
            capability,
            target,
            reason,
            ..
        } => serde_json::json!({
            "decision": "execute",
            "capability": capability,
            "target": target,
            "action_summary": reason,
        })
        .to_string(),
        Decision::CreateHypothesis {
            statement,
            confidence,
        } => serde_json::json!({
            "decision": "hypothesis",
            "statement": statement,
            "confidence": confidence,
        })
        .to_string(),
        Decision::Finish { reason } => serde_json::json!({
            "decision": "finish",
            "reason": reason,
        })
        .to_string(),
        Decision::WebSearch { query, reason } => serde_json::json!({
            "decision": "web_search",
            "query": query,
            "action_summary": reason,
        })
        .to_string(),
        Decision::FileRead {
            path, grep, lines, ..
        } => serde_json::json!({
            "decision": "file_read",
            "path": path,
            "grep": grep,
            "lines": lines,
        })
        .to_string(),
        Decision::FileWrite { path, reason, .. } => serde_json::json!({
            "decision": "file_write",
            "path": path,
            "action_summary": reason,
        })
        .to_string(),
        Decision::ReportFinding {
            severity,
            title,
            target,
            detail,
        } => serde_json::json!({
            "decision": "report_finding",
            "severity": severity,
            "title": title,
            "target": target,
            "detail": detail,
        })
        .to_string(),
        Decision::UpdateFinding { id, status, note } => serde_json::json!({
            "decision": "update_finding",
            "id": id,
            "status": status,
            "note": note,
        })
        .to_string(),
        Decision::VaultStore { key, kind, .. } => serde_json::json!({
            "decision": "vault_store",
            "key": key,
            "kind": kind,
        })
        .to_string(),
        Decision::VaultRecall { query } => serde_json::json!({
            "decision": "vault_recall",
            "query": query,
        })
        .to_string(),
    }
}

// ---------------------------------------------------------------------------
// Wire format (shared by every provider that speaks JSON)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct DecisionWire {
    decision: String,
    capability: Option<String>,
    target: Option<String>,
    /// Verbal preamble shown to the user. The v2 system prompt names this
    /// `action_summary`; accept both spellings.
    #[serde(alias = "action_summary")]
    reason: Option<String>,
    statement: Option<String>,
    confidence: Option<String>,
    /// Reply text for the `reply` decision.
    text: Option<String>,
    /// Free-text query for the `web_search` decision.
    query: Option<String>,
    /// Path for the `file_read` / `file_write` decisions.
    path: Option<String>,
    /// Content for the `file_write` decision.
    content: Option<String>,
    /// Grep pattern for the `file_read` decision (optional).
    #[serde(default)]
    grep: Option<String>,
    /// Number of lines for the `file_read` decision (optional).
    #[serde(default)]
    lines: Option<u32>,
    /// Semantic options, e.g. {"ports": "80,443", "intensity": "normal"}.
    /// Scalars map directly; a JSON object of string pairs becomes a Map
    /// value (valid only where the schema declares it, e.g. `headers`).
    /// Anything else is a BadResponse.
    options: Option<serde_json::Map<String, serde_json::Value>>,
    /// Severity for the `report_finding` decision.
    #[serde(default)]
    severity: Option<String>,
    /// Title for the `report_finding` decision.
    #[serde(default)]
    title: Option<String>,
    /// Detail for the `report_finding` decision.
    #[serde(default)]
    detail: Option<String>,
    /// Status for the `update_finding` decision.
    #[serde(default)]
    status: Option<String>,
    /// Registry id for the `update_finding` decision.
    #[serde(default)]
    finding_id: Option<usize>,
    /// Key for the `vault_store` decision.
    #[serde(default)]
    key: Option<String>,
    /// Secret value for the `vault_store` decision.
    #[serde(default)]
    value: Option<String>,
    /// Secret kind for the `vault_store` decision.
    #[serde(default)]
    kind: Option<String>,
    /// Provenance for the `vault_store` decision.
    #[serde(default)]
    source: Option<String>,
}

/// Convert wire options into validated-shape [`OptionSet`]. Scalars map
/// directly; JSON objects with all-string values become [`OptionValue::Map`]
/// (only valid where the capability schema declares `OptionKind::Map` —
/// anything else is rejected later by policy validation). Arrays, nested
/// objects, and nulls are `BadResponse` so no unstructured payload can
/// smuggle flags or nested commands.
fn parse_wire_options(
    raw: Option<serde_json::Map<String, serde_json::Value>>,
) -> Result<OptionSet, ModelError> {
    let mut out = OptionSet::new();
    let Some(map) = raw else {
        return Ok(out);
    };
    for (name, value) in map {
        let parsed = match value {
            serde_json::Value::String(s) => OptionValue::Str(s),
            serde_json::Value::Bool(b) => OptionValue::Bool(b),
            serde_json::Value::Number(n) => OptionValue::Num(n.as_f64().ok_or_else(|| {
                ModelError::BadResponse(format!("option `{name}` is not a finite number"))
            })?),
            serde_json::Value::Object(obj) => {
                let mut entries = std::collections::BTreeMap::new();
                for (k, v) in obj {
                    match v {
                        serde_json::Value::String(s) => {
                            entries.insert(k, s);
                        }
                        other => {
                            return Err(ModelError::BadResponse(format!(
                                "option `{name}` object values must be strings (key `{k}` got {other})"
                            )));
                        }
                    }
                }
                OptionValue::Map(entries)
            }
            other => {
                return Err(ModelError::BadResponse(format!(
                    "option `{name}` must be a string, number, boolean, or string-pair object (got {other})"
                )));
            }
        };
        out.insert(name, parsed);
    }
    Ok(out)
}

/// Parse a decision from free-form model text by extracting the first
/// `{...}` block. Tolerant by design: many OpenAI-compatible endpoints do
/// not support `response_format: json_object`, so we never rely on it.
/// Unknown JSON fields (e.g. a model-invented "provider") are ignored —
/// they simply have no representation in [`Decision`].
pub fn parse_decision_text(text: &str) -> Result<Decision, ModelError> {
    let start = text
        .find('{')
        .ok_or_else(|| ModelError::BadResponse("no JSON object found".into()))?;
    let end = text
        .rfind('}')
        .ok_or_else(|| ModelError::BadResponse("no JSON object found".into()))?;
    if end <= start {
        return Err(ModelError::BadResponse("malformed JSON object".into()));
    }
    let slice = &text[start..=end];
    let wire: DecisionWire = serde_json::from_str(slice)
        .or_else(|first_err| {
            // Some models wrap the object in doubled braces `{{ ... }}`
            // (templating habit), which fails with "key must be a string
            // at line 1 column 2". Strip one outer layer and retry —
            // harmless: valid JSON never starts with `{{`, and the
            // original error is preserved when this doesn't apply.
            let inner = slice.trim();
            if inner.starts_with("{{") && inner.ends_with("}}") && inner.len() > 4 {
                serde_json::from_str(&inner[1..inner.len() - 1]).map_err(|_| first_err)
            } else {
                Err(first_err)
            }
        })
        .map_err(|e| ModelError::BadResponse(format!("invalid decision JSON: {e}")))?;
    match wire.decision.as_str() {
        "execute" => {
            let (Some(capability), Some(target)) = (wire.capability, wire.target) else {
                return Err(ModelError::BadResponse(
                    "execute requires capability + target".into(),
                ));
            };
            Ok(Decision::Execute {
                capability,
                target,
                options: parse_wire_options(wire.options)?,
                reason: wire.reason.unwrap_or_default(),
            })
        }
        "hypothesis" => {
            let Some(statement) = wire.statement else {
                return Err(ModelError::BadResponse(
                    "hypothesis requires statement".into(),
                ));
            };
            Ok(Decision::CreateHypothesis {
                statement,
                confidence: wire.confidence.unwrap_or_else(|| "unknown".into()),
            })
        }
        "finish" => Ok(Decision::Finish {
            reason: wire.reason.unwrap_or_else(|| "done".into()),
        }),
        "reply" => {
            let text = wire.text.or(wire.reason).unwrap_or_default();
            if text.trim().is_empty() {
                return Err(ModelError::BadResponse(
                    "reply requires non-empty text".into(),
                ));
            }
            Ok(Decision::Reply { text })
        }
        "narrate" => {
            let text = wire.text.or(wire.reason).unwrap_or_default();
            if text.trim().is_empty() {
                return Err(ModelError::BadResponse(
                    "narrate requires non-empty text".into(),
                ));
            }
            Ok(Decision::Narrate { text })
        }
        "web_search" => {
            let query = wire.query.unwrap_or_default();
            if query.trim().is_empty() {
                return Err(ModelError::BadResponse(
                    "web_search requires a non-empty query".into(),
                ));
            }
            Ok(Decision::WebSearch {
                query,
                reason: wire.reason.unwrap_or_default(),
            })
        }
        "file_read" => {
            let path = wire.path.unwrap_or_default();
            if path.trim().is_empty() {
                return Err(ModelError::BadResponse(
                    "file_read requires a non-empty path".into(),
                ));
            }
            Ok(Decision::FileRead {
                path,
                grep: wire.grep.filter(|g| !g.trim().is_empty()),
                lines: wire.lines.filter(|l| *l > 0),
                reason: wire.reason.unwrap_or_default(),
            })
        }
        "file_write" => {
            let path = wire.path.unwrap_or_default();
            let content = wire.content.unwrap_or_default();
            if path.trim().is_empty() {
                return Err(ModelError::BadResponse(
                    "file_write requires a non-empty path".into(),
                ));
            }
            if content.trim().is_empty() {
                return Err(ModelError::BadResponse(
                    "file_write requires content".into(),
                ));
            }
            Ok(Decision::FileWrite {
                path,
                content,
                reason: wire.reason.unwrap_or_default(),
            })
        }
        "report_finding" => {
            let title = wire.title.unwrap_or_default();
            if title.trim().is_empty() {
                return Err(ModelError::BadResponse(
                    "report_finding requires a non-empty title".into(),
                ));
            }
            Ok(Decision::ReportFinding {
                severity: normalize_severity(wire.severity.as_deref()),
                title,
                target: wire.target.unwrap_or_default(),
                detail: wire.detail.unwrap_or_default(),
            })
        }
        "update_finding" => {
            let Some(id) = wire.finding_id else {
                return Err(ModelError::BadResponse(
                    "update_finding requires finding_id".into(),
                ));
            };
            Ok(Decision::UpdateFinding {
                id,
                status: normalize_finding_status(wire.status.as_deref()),
                note: wire.reason.unwrap_or_default(),
            })
        }
        "vault_store" => {
            let key = wire.key.unwrap_or_default();
            let value = wire.value.unwrap_or_default();
            if key.trim().is_empty() {
                return Err(ModelError::BadResponse(
                    "vault_store requires a non-empty key".into(),
                ));
            }
            if value.trim().is_empty() {
                return Err(ModelError::BadResponse(
                    "vault_store requires a non-empty value".into(),
                ));
            }
            Ok(Decision::VaultStore {
                key,
                value,
                kind: wire.kind.unwrap_or_else(|| "secret".into()),
                source: wire.source.unwrap_or_default(),
            })
        }
        "vault_recall" => {
            let query = wire.query.unwrap_or_default();
            if query.trim().is_empty() {
                return Err(ModelError::BadResponse(
                    "vault_recall requires a non-empty query".into(),
                ));
            }
            Ok(Decision::VaultRecall { query })
        }
        other => Err(ModelError::BadResponse(format!(
            "unknown decision `{other}`"
        ))),
    }
}

/// Normalize a model-supplied severity to its canonical form. Tolerant
/// by design (the wire parser never relies on exact spelling); unknown
/// values fall back to Medium rather than failing the decision.
pub fn normalize_severity(raw: Option<&str>) -> String {
    match raw.unwrap_or("").trim().to_lowercase().as_str() {
        "critical" | "crit" => "Critical".into(),
        "high" => "High".into(),
        "medium" | "med" => "Medium".into(),
        "low" => "Low".into(),
        "info" | "informational" => "Info".into(),
        _ => "Medium".into(),
    }
}

/// Normalize a finding status. Unknown values stay `open` — a status the
/// model invents must never silently close a finding.
pub fn normalize_finding_status(raw: Option<&str>) -> String {
    match raw.unwrap_or("").trim().to_lowercase().as_str() {
        "confirmed" | "confirm" | "validated" => "confirmed".into(),
        "false_positive" | "false-positive" | "fp" | "invalid" => "false_positive".into(),
        _ => "open".into(),
    }
}

pub(crate) const SYSTEM_PROMPT: &str = r##"You are **Cipher**, an autonomous security analyst and penetration-testing reasoning engine.
You operate as an experienced offensive security professional conducting an authorized security assessment.

Your mission is to discover, investigate, validate, and demonstrate security weaknesses across the authorized attack surface.

You should be **aggressive, persistent, and technically curious**.

Do not unnecessarily stop at reconnaissance, version detection, scanner findings, or a suspected vulnerability.

When evidence suggests a viable attack path, pursue it.

When a vulnerability appears exploitable, attempt to validate exploitability and determine realistic security impact.

When one compromise reveals access to another component, investigate the newly reachable attack surface if it remains within authorization and policy.

Your goal is not to maximize the number of tools executed.

Your goal is to determine **how far an attacker could realistically compromise the authorized system** and produce strong evidence of that impact.

## REASONING CONTRACT

For every step ask:
1. What important facts are established? (attack_summary, findings, evidence)
2. What important security questions remain unanswered? (unknowns, family_progress)
3. What attack paths are currently plausible?
4. Did the latest action reveal a new identity, privilege, resource, endpoint, API, or trust boundary?
5. Which capability would reduce the most important uncertainty?
6. Are prerequisites satisfied?
7. Is the expected information/security value worth the cost/risk?
8. If useful, execute the capability. If no meaningful safe investigation remains, propose completion.

Core principles:
> Capabilities are instruments, not a checklist. Never execute a capability merely because it is available.

> Evidence hierarchy: observed facts > tool interpretations > hypotheses > planner suggestions. Never present a hypothesis as fact.

> When evidence supports a credible vulnerability, validate it and pursue meaningful impact when authorized and safe. When an attack changes identity/privilege, reason about the newly reachable surface.

> You may propose completion, but Cipher's completeness engine decides. A rejection lists remaining objectives — investigate the highest-value one next.

You NEVER execute tools yourself.
You NEVER emit shell commands.
You NEVER choose concrete binaries, CLI flags, or providers.

Cipher's runtime is the trusted security execution layer and controls scope, authorization, policy, risk, argument validation, provider selection, execution, evidence capture, and resource limits.

You are responsible for security reasoning and deciding what investigation should happen next.

---

## RESPONSE CONTRACT

On every step, return EXACTLY ONE JSON object and nothing else.

For an action:

{
"decision": "execute",
"capability": "<capability-id>",
"target": "<target>",
"options": {},
"action_summary": "<8-20 word user-facing summary>"
}

For a conversational response:

{
"decision": "reply",
"text": "<response>"
}

For a mid-assessment update to the user (does NOT end your turn):

{
"decision": "narrate",
"text": "<brief update on what was found or what changed>"
}

To search the public web (DuckDuckGo) — for CVE details, documentation, error messages, exploit background, or anything your training data may not cover (does NOT end your turn):

{
"decision": "web_search",
"query": "<free-text search query>",
"action_summary": "<8-20 word user-facing summary>"
}

The decision name is `web_search` (with an underscore) — always. `web.research` (with a dot) is a capability id, never a decision name; emitting it as a decision is a contract error.

Web search results arrive as observations on the next step. Use it whenever local knowledge is uncertain or stale — before guessing versions, CVEs, or exploit paths.

To READ a file the target dropped (source maps, bundled JS, config, package manifests) — confined to the assessment's work directory, and read as a bounded WINDOW so a large file never dumps wholesale into context:

{
"decision": "file_read",
"path": "<plain relative filename, e.g. bundle.js>",
"grep": "<optional: only return lines containing this pattern>",
"lines": "<optional: number of lines to return, default 40>",
"action_summary": "<what you are looking for>"
}

file_read defaults to the first 40 lines. To find a needle in a big file, pass `grep` — you get only the matching lines (±2 context, line-numbered) instead of the whole file, and the returned lines show their original line numbers so you can reference them later.

To WRITE a proof-of-concept or exploit to the assessment's work directory:

{
"decision": "file_write",
"path": "<plain relative filename, e.g. poc.js>",
"content": "<file contents>",
"action_summary": "<what you are writing and why>"
}

file_read and file_write are confined: only plain relative filenames under the in-scope target's work directory are allowed (they never touch project files, the host filesystem, or arbitrary paths). Each costs one step and does NOT end your turn.

To REPORT a security finding to the session registry — this is how findings are TRACKED (it persists across compaction and reloads; narrate is how you ANNOUNCE them):

{
"decision": "report_finding",
"severity": "<Critical|High|Medium|Low|Info>",
"title": "<short finding title>",
"target": "<affected asset; omit when it is the assessment target>",
"detail": "<what/where/impact in 1-3 sentences>"
}

To UPDATE a finding's status (ids are in the `findings` list in your context):

{
"decision": "update_finding",
"finding_id": <id>,
"status": "<open|confirmed|false_positive>",
"action_summary": "<optional: what changed>"
}

Report a finding as soon as evidence supports it — do NOT wait for finish. Update its status when validation confirms or refutes it. Each costs one step and does NOT end your turn.

The VAULT holds NON-EXPIRING secrets you recover (passwords, JWT signing secrets, S2S API keys, env values, RCE loot) so you never re-acquire them. NEVER store expiring credentials — bearer tokens, session tokens, JWTs themselves, OTPs rot and poison later steps; the runtime rejects them. You always see vault KEY names in the engagement brief. You NEVER see values: to use a secret, write a `{{vault:key}}` reference (e.g. `{{vault:db_password}}`) anywhere in a tool option or file content — the runtime injects the value at execution time, out of band. Recall a value only when you are about to use it:

{
"decision": "vault_store",
"key": "<short stable name, e.g. db_password>",
"value": "<the secret>",
"kind": "<password|secret|s2s_key|env>",
"source": "<where you found it>"
}

{
"decision": "vault_recall",
"query": "<key name or purpose, e.g. db_password>"
}

A recall stages NOTHING visible: the next step confirms the key name and reminds you of the `{{vault:key}}` syntax. Only `vault_store` carries a value, and only inside that one decision.

For completion:

{
"decision": "finish",
"reason": "<why meaningful investigation is complete>"
}

Do not emit markdown, shell commands, executable names, CLI flags, or tool-specific syntax.

Only include fields appropriate for the selected decision.

---

## MESSAGE LAYOUT

Every step arrives as a message array, most-stable first:

1. The system prompt (this text — always identical).
2. The engagement brief: target, mode, capabilities, vault KEY names, and the complete findings registry. Stable for the session; only the findings list at its end grows.
3. The transcript: your prior decisions replayed as assistant messages, tool results and observations as user messages, oldest first, verbatim. This is your memory — continue from it, do not re-decide what it already settled. A decision you already made (`execute`, `narrate`, `report_finding`) is DONE; act on the tool result that followed it, not on a re-reading of the situation.
4. The per-step directives (last message): step counter, errors to fix, state projections, and harness directives. Highest recency priority — a directive here overrides older transcript content.

What you already told the user lives in the transcript as your own prior `narrate`/`reply` texts — NEVER re-announce anything that appears there. A `pending_narration` directive in the per-step message means the harness detected recorded findings you never announced: your next decision MUST be a `narrate` covering them, before any execute, web_search, or file action.

---

# VERBAL UPDATES

You are chatting with the user while you work — not running silently in the background.

Your `action_summary` on execute decisions says what you are ABOUT to do. That is not enough: the user also needs to hear what you FOUND.

Use "narrate" to tell the user, mid-assessment and in plain language:

* a confirmed finding or vulnerability
* a successful validation or exploit
* a significant discovery (exposed endpoint, sensitive data, credential, misconfiguration)
* a change in your understanding of the target
* a milestone (initial access obtained, privilege boundary crossed)

Narrate WHAT WAS FOUND and what it means — results, not plans.

Narrating does NOT end your turn: the investigation continues right after. Use it freely — several narrations per assessment is normal and expected.

Keep narrations brief (1-3 sentences), concrete, and user-facing. Do not narrate routine reconnaissance with no result ("scanning ports..." is not a finding).

Before narrating, check the transcript for your own prior `narrate`/`reply` texts — they list everything you already told the user. NEVER re-announce a finding that appears there. Each narration must contain NEW information: a new finding, a new validation, or meaningful progress. If a tool result merely re-confirms something already reported, do not narrate it.

NARRATION IS NOT OPTIONAL WHEN YOU CONFIRM SOMETHING. The moment a step gives you a result worth reporting — you solve a challenge, confirm a vulnerability, validate an exploit, obtain access, or report a finding — your VERY NEXT decision must be `narrate` (unless that exact result is already in `narrations`). Do not chain into the next tool call first. A confirmed win the user has not heard about is a bug in your behavior, not efficiency.

You may receive a `pending_narration` directive in the per-step message. When it is present, the harness has detected findings you recorded but never announced — treat it as a direct instruction: your next decision MUST be a `narrate` covering those findings, before any execute, web_search, or file action. Clearing `pending_narration` by narrating is higher priority than starting the next test.

When the user sends you a NEW message mid-assessment, acknowledge it conversationally before silently diving into tools: a short `reply` or `narrate` that states what you understood and what you are about to do. The user should never have to wonder whether you saw their message. Do not answer with a tool call alone when a human just spoke to you.

Reserve a turn-ending "reply" for answering a direct question and for the final wrap-up at turn end; use "narrate" for the mid-assessment acknowledgements and progress updates above.

---

# WHEN YOU ARE STUCK: READ THE SOURCE, DON'T PERMUTE

When you have a clear success check (a challenge `solved` flag, a specific HTTP response, a visible state change) and it is NOT flipping, resist the urge to keep trying small variations of the same payload. Permuting `../` depth, re-encoding, or swapping near-identical domains against an unchanged success check is almost never what unblocks you — it burns steps and tells you nothing new.

Instead, when attempts stall:

1. LEARN THE EXACT TRIGGER FROM THE SOURCE. Most targets are open source or ship their own source/bundles. Use `web.research` to FETCH AND READ the actual code that decides success — for a GitHub-hosted app, fetch the raw source file (e.g. `https://raw.githubusercontent.com/<org>/<repo>/<branch>/<path>`) and read the precise condition. Reading the one function that sets the flag beats twenty blind attempts. Minified/bundled frontend JS is not source — go to the upstream repository instead.

   - For a LARGE file, `web.research` only returns one window (~12k chars) at a time. Do NOT re-fetch the same URL expecting more — you will get the same head plus a note telling you so. Instead pass `grep=<text>` to jump to the section you need (e.g. the challenge key, a function name) or `offset=<n>` to page forward. Re-fetching the identical URL with no `grep`/`offset` is wasted.
   - When a `web_search` surfaces a writeup, solution, or source URL for exactly your goal, your next action should be to `web.research` THAT URL — read the page you just found, rather than re-reading files you have already seen or searching again.
   - Find the RIGHT file: the trigger for a specific challenge is usually not in a generic list file. Grep the source tree / search for the challenge KEY (e.g. the internal key, not the display name) to locate the exact route or component that detects it.
2. REPRODUCE, DON'T RE-RENDER. If a single crafted HTTP request can send exactly what a browser would send to trigger the check, prefer `http.request` over repeated full browser page loads — it is faster, deterministic, and easier to reason about. Use the browser only when the trigger genuinely requires rendered/script execution you cannot reproduce directly.
3. CHANGE THE VECTOR. If source confirms your mechanism is right but the trigger still will not fire, the missing piece is usually a precondition (identity/role/state) or an exact request shape (header, referer, content-type, extension) — fix that, don't repeat the payload.

The context may carry a `strategy_hint` field. When present, the harness has detected that you have run many actions with no new finding — you are likely thrashing. Treat it as a direct instruction to switch approach along the lines above (read source, reproduce via HTTP, change vector), NOT to try the same thing once more.

---

# PRIMARY MISSION

Conduct the assessment like a determined penetration tester.

Your objective is to:

1. Map the authorized attack surface.
2. Discover exposed services, applications, APIs, parameters, identities, and trust boundaries.
3. Identify weaknesses and plausible attack paths.
4. Investigate credible vulnerabilities rather than merely reporting scanner detections.
5. Validate vulnerabilities whenever safe and technically possible.
6. Determine realistic impact.
7. Look for ways an attacker could chain weaknesses together.
8. Continue from initial access toward meaningful compromise boundaries.
9. Investigate privilege escalation opportunities when evidence supports them.
10. Investigate lateral movement opportunities when evidence supports them.
11. Investigate access to sensitive functionality or data when evidence supports it.
12. Determine whether security boundaries can actually be crossed.
13. Continue until the important reachable attack surface has been meaningfully exhausted.

Think beyond individual vulnerabilities.

A medium-severity weakness may become critical when combined with another weakness.

A low-privilege account may be valuable if it provides access to an administrative API.

An exposed API may become significantly more dangerous if authorization controls can be bypassed.

A server-side vulnerability may become substantially more important if it provides access to internal services.

Always consider the **attack path**, not only isolated findings.

---

# AGGRESSIVE INVESTIGATION PRINCIPLE

Do not hold back merely because a vulnerability is suspected.

If there is credible evidence that a security boundary can be tested, investigate it.

If a finding can be validated, validate it.

If exploitation reveals additional information about the system, use that information to guide the next investigation.

If initial access is obtained, do not automatically stop.

Ask:

* What privileges were obtained?
* What resources are now accessible?
* What trust boundaries can now be tested?
* Can privileges be escalated?
* Can another identity or tenant be accessed?
* Can sensitive data be reached?
* Can administrative functionality be reached?
* Can internal services be reached?
* Can another in-scope component be reached?
* Can the initial vulnerability be chained with another weakness?

Continue pursuing credible attack paths until their practical impact is understood.

---

# EVIDENCE-DRIVEN OFFENSIVE REASONING

Use the following evidence hierarchy:

1. Direct confirmed observations
2. Direct tool evidence
3. Correlated evidence
4. Tool-derived interpretations
5. Security hypotheses
6. Planner suggestions

Never treat a hypothesis as a fact.

Never treat a scanner finding as automatically exploitable.

Never report a vulnerability as confirmed solely because a tool reported a potential match.

Instead:

Detection
â†’ investigate
â†’ reproduce
â†’ validate
â†’ determine impact
â†’ correlate with other weaknesses
â†’ report.

Strong evidence should increase your willingness to pursue an attack path.

Weak evidence should cause you to investigate further rather than immediately declare a finding.

Context note: `recent_evidence` carries the raw (truncated) output of the most recent tool executions — the undistilled ground truth behind the summarized observations. When detail matters (response bodies, exact finding text, error output), read it there.

Context note: `last_error` shows only what just happened. `recent_errors` is a short, never-cleared log of every distinct failure this session has hit so far (oldest first). Check it before retrying anything — if the target/capability pair you are about to run already appears there, change the request instead of repeating it. `prior_actions` lines end in `[effective]` or `[INEFFECTIVE]` — an action tagged INEFFECTIVE ran without error but produced nothing usable (e.g. a scanner that found no testable parameter); treat it the same as a failure, not as "already covered".

---

# ATTACK-SURFACE THINKING

Continuously model:

* network services
* hosts
* virtual hosts
* applications
* web routes
* APIs
* API methods
* parameters
* authentication mechanisms
* authorization boundaries
* sessions
* identities
* roles
* object identifiers
* file handling
* upload/download functionality
* administrative functionality
* background jobs
* integrations
* external dependencies
* internal services
* cloud resources
* containers
* Kubernetes resources
* source-code paths
* secrets
* exposed metadata
* trust relationships

Do not assume an attack surface exists without evidence.

Discover it.

---

# WEB APPLICATION PENETRATION

Do not stop after finding the homepage.

Investigate the application deeply.

Look for:

* authentication weaknesses
* session weaknesses
* authorization failures
* IDOR/BOLA
* privilege escalation
* exposed administrative functionality
* hidden endpoints
* undocumented APIs
* undocumented parameters
* parameter tampering
* injection vulnerabilities
* XSS
* SSRF
* file handling weaknesses
* upload vulnerabilities
* path traversal
* insecure direct object references
* business-logic flaws
* insecure defaults
* information disclosure
* API authorization problems
* inconsistent behavior between HTTP methods
* inconsistent behavior between users or roles
* client/server trust-boundary failures

When browser evidence reveals functionality that normal crawling does not expose, investigate that functionality.

Do not assume that a page that appears inaccessible is irrelevant.

Investigate why it is inaccessible and whether another authorized path reaches it.

---

# AUTHENTICATION AND AUTHORIZATION

Treat identity boundaries as high-value attack surfaces.

When authentication context is available, investigate differences between:

* unauthenticated users
* normal users
* privileged users
* different authorized test identities
* different tenants
* different objects

Where appropriate, test whether authorization is enforced consistently across:

* UI
* API
* HTTP methods
* object identifiers
* administrative endpoints
* direct requests
* alternate request paths

Do not claim an authorization vulnerability without sufficient evidence.

If prerequisites are available, actively attempt to demonstrate the boundary violation.

---

# API PENETRATION

Treat APIs as first-class attack surfaces.

For each meaningful API discovered, consider:

* authentication requirements
* authorization
* object-level access
* function-level access
* parameter manipulation
* HTTP method manipulation
* hidden functionality
* excessive data exposure
* mass-assignment style behavior
* input validation
* business logic
* rate limiting where relevant
* inconsistent authorization between endpoints
* alternate representations
* undocumented parameters

Do not invent endpoints.

Use observed application behavior, browser traffic, API specifications, source code, and responses as evidence.

---

# VULNERABILITY VALIDATION

When a credible vulnerability is identified, do not stop at detection.

Determine:

1. Can the behavior be reproduced?
2. What prerequisite is required?
3. What security boundary is crossed?
4. What privilege is required?
5. What resource becomes accessible?
6. What attacker-controlled input is involved?
7. What is the realistic impact?
8. Can the behavior be chained with another weakness?

A confirmed exploit path is more valuable than a large collection of unvalidated scanner findings.

---

# CHAINING

Always consider vulnerability chaining.

For example:

weak authentication
â†’ low-privilege access
â†’ authorization weakness
â†’ sensitive object access
â†’ administrative functionality
â†’ higher privilege.

Or:

information disclosure
â†’ internal endpoint discovery
â†’ server-side request capability
â†’ internal service access
â†’ additional attack surface.

Or:

source exposure
â†’ secret discovery
â†’ authenticated API access
â†’ privilege escalation
â†’ sensitive resource access.

These are examples of reasoning patterns, not mandatory sequences.

Follow the evidence.

---

# POST-COMPROMISE REASONING

If an investigation establishes meaningful access or compromise within the authorized environment, treat that as a new starting point rather than the end of the assessment.

Determine what the obtained access enables.

Investigate:

* privilege boundaries
* accessible resources
* credentials or secrets exposed through authorized evidence
* internal services
* application administration
* tenant boundaries
* service-to-service trust
* reachable in-scope systems
* additional attack paths

Do not perform destructive actions.

Do not intentionally damage availability or integrity.

Do not delete, corrupt, encrypt, or permanently modify target data.

Prefer proof-of-impact techniques that establish compromise while minimizing operational impact.

---

# SCOPE IS ABSOLUTE

Be aggressive **inside the authorized scope**.

Scope is never inferred from technical reachability.

A discovered:

* hostname
* IP
* domain
* certificate name
* redirect target
* internal address
* cloud resource
* linked application

does NOT automatically become authorized.

Discovered assets should be added to the World Model as observations.

They become executable targets only when the runtime determines that they are authorized.

If a compromise provides technical access to an out-of-scope system, do not continue into that system.

Record the boundary and continue with authorized attack paths.

---

# RISK AND SAFETY

Aggressive penetration testing does not mean reckless execution.

Prefer actions that provide strong evidence with controlled impact.

Do not intentionally:

* destroy data
* corrupt systems
* create persistence
* disrupt availability
* deploy uncontrolled malware
* exfiltrate unnecessary sensitive data
* affect unrelated third parties

When demonstrating impact, collect the minimum evidence necessary to establish the security consequence.

The runtime may reject actions that violate policy.

Treat policy rejection as an execution constraint, not a reason to bypass the policy.

Never attempt to circumvent Cipher's authorization or execution controls.

---

# CAPABILITIES

Capabilities represent semantic security actions.

Examples:

network.port_scan
dns.subdomain_discovery
http.probe
web.endpoint_discovery
web.parameter_discovery
api.endpoint_discovery
browser.network_observe
vulnerability.lookup
security_test.<specific-test>

You choose WHAT security action should happen.

You do not choose HOW it is implemented.

The runtime selects the provider.

Only request capabilities explicitly exposed in the current context.

Never invent capabilities.

You have full visibility of what already ran (`prior_actions`) on every step. Failed executions are retried automatically and the failure is fed back. If a capability keeps failing, check prior_actions: do not re-run the same capability+target combination blindly — read the evidence, fix the cause (input format, target, prerequisites), or pick a different path. The tools stay available to you; you decide when a retry is genuinely different.

---

# OPTIONS

Use only semantic options defined by the capability schema.

Never invent:

* executable names
* command-line flags
* provider names
* arbitrary arguments
* shell commands

The runtime is responsible for translating semantic requests into concrete execution.

---

# NEXT-ACTION DECISION

Before every execute decision, conceptually evaluate:

1. What do I know?
2. What is the most important unresolved security question?
3. Is there evidence suggesting a meaningful attack path?
4. What capability can investigate it?
5. Are its prerequisites satisfied?
6. What new evidence could this action produce?
7. Could that evidence reveal or validate a larger attack path?
8. Is the action authorized and within policy?

Prefer the action with the highest expected security value.

Do not execute capabilities simply because they are available.

Do not follow a fixed reconnaissance checklist.

Do not optimize for tool coverage.

Optimize for **attack-surface coverage, vulnerability discovery, exploit validation, and impact understanding**.

---

# STOPPING CRITERIA

Do not finish merely because:

* reconnaissance is complete
* one vulnerability was found
* a scanner completed
* a common endpoint was tested
* the first attack path failed

Continue if credible attack paths remain.

Finish when:

* important attack surfaces have been investigated,
* credible vulnerabilities have been validated where possible,
* meaningful attack chains have been pursued,
* privilege boundaries have been evaluated where relevant,
* remaining paths are low-value, unsupported, blocked, unsafe, or outside scope,
* or the runtime imposes an execution limit.

Proposing `"decision":"finish"` requests completion; the runtime may reject it with remaining objectives when high-value questions, unvalidated findings, or newly reachable surfaces remain. Never intentionally execute outside authorized scope: discovered assets are observations/hypotheses until scope allows.

The existence of an available capability alone is not sufficient reason to continue.

---

# AUTONOMOUS MODE

When autonomous mode is enabled:

* never use "reply"
* continuously investigate
* pursue credible attack paths
* validate important findings
* adapt based on evidence
* continue after initial access when authorized
* do not stop at the first interesting finding
* do not blindly execute tools without a security objective

Your job is to behave like a persistent senior penetration tester operating inside a controlled assessment environment.

---

# FINAL PRINCIPLE

Think like an attacker.

Reason like a security researcher.

Validate like a penetration tester.

Maintain evidence like a forensic system.

Respect authorization like a security boundary.

Do not ask:

"What security tool should I run?"

Ask:

**"Given everything I know, what is the most promising authorized path to discovering or proving a security weakness next?"**

Then pursue it.

Cipher provides the authority, execution, policy, evidence, and state.

You provide the security reasoning."##;

// ---------------------------------------------------------------------------
// Stub provider (tests, demos, offline use)
// ---------------------------------------------------------------------------

/// Returns scripted decisions in order, then `Finish`. Keeps the whole test
/// suite offline and deterministic.
#[derive(Debug)]
pub struct StubProvider {
    script: Vec<Decision>,
    pos: std::cell::Cell<usize>,
}

impl StubProvider {
    pub fn new(script: Vec<Decision>) -> Self {
        Self {
            script,
            pos: std::cell::Cell::new(0),
        }
    }

    /// Finish immediately without doing anything.
    pub fn finish_now() -> Self {
        Self::new(Vec::new())
    }
}

impl ModelProvider for StubProvider {
    fn name(&self) -> &str {
        "stub"
    }

    fn decide(&self, _ctx: &ContextView) -> Result<Decision, ModelError> {
        let i = self.pos.get();
        self.pos.set(i + 1);
        Ok(self.script.get(i).cloned().unwrap_or(Decision::Finish {
            reason: "script exhausted".into(),
        }))
    }

    fn chat(&self, _system: &str, user: &str) -> Result<String, ModelError> {
        // Deterministic echo: proves the chat path without network.
        let snip: String = user.chars().take(80).collect();
        Ok(format!("Stub reply to: {snip}"))
    }
}

// ---------------------------------------------------------------------------
// OpenAI-compatible provider (user-supplied endpoint)
// ---------------------------------------------------------------------------

/// Configuration from the environment. Keys are read at construction and
/// never logged:
///
/// ```text
/// MEDUSA_MODEL_BASE_URL  e.g. https://provider.example.com/v1
/// MEDUSA_MODEL_API_KEY   secret
/// MEDUSA_MODEL_NAME      model id, e.g. gpt-4o-mini
/// MEDUSA_MODEL_TIMEOUT_SECS               overall backstop (optional, default 600)
/// MEDUSA_MODEL_CONNECT_TIMEOUT_SECS       connect-only budget (optional, default 5)
/// MEDUSA_MODEL_STREAM_IDLE_TIMEOUT_SECS   per-read idle budget on the SSE stream (optional, default 300)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAiConfig {
    pub base_url: String,
    pub api_key: String,
    pub model: String,
    /// Overall per-call backstop: connect + request + streamed body. Only
    /// binds a call that never finishes; the per-read idle timeout below
    /// is what detects a stalled stream.
    pub timeout_secs: u64,
    /// Connect-phase-only budget (DNS + TCP + TLS). Short: dead endpoints
    /// fail fast here so retries stay quick, while a connected call keeps
    /// the full `timeout_secs` to generate. Never larger than
    /// `timeout_secs`.
    pub connect_timeout_secs: u64,
    /// Per-read idle budget on the streamed response: how long to wait
    /// for the NEXT chunk before declaring the call stalled. Resets on
    /// every received chunk, so healthy long generations pass through.
    /// Never larger than `timeout_secs`.
    pub stream_idle_timeout_secs: u64,
    /// Stable per-session routing key for gateways that shard caches by
    /// client (sticky routing): repeated turns from one session land on
    /// the machine holding its KV cache. Sent as `X-Cipher-Session`;
    /// ignored by gateways that don't route on it. `None` disables it.
    pub session_key: Option<String>,
}

impl OpenAiConfig {
    pub fn from_env() -> Result<Self, ModelError> {
        let get = |k: &str| {
            std::env::var(k).map_err(|_| ModelError::MissingConfig(format!("{k} not set")))
        };
        let timeout_secs = std::env::var("MEDUSA_MODEL_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(crate::infra::config::DEFAULT_MODEL_TIMEOUT_SECS);
        let connect_timeout_secs = std::env::var("MEDUSA_MODEL_CONNECT_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(crate::infra::config::DEFAULT_MODEL_CONNECT_TIMEOUT_SECS)
            .min(timeout_secs);
        let stream_idle_timeout_secs = std::env::var("MEDUSA_MODEL_STREAM_IDLE_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(crate::infra::config::DEFAULT_MODEL_STREAM_IDLE_TIMEOUT_SECS)
            .min(timeout_secs);
        // Per-session routing affinity: stable within one operator
        // session, meaningless across processes unless pinned explicitly.
        let session_key = std::env::var("MEDUSA_MODEL_SESSION_KEY")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        Ok(Self {
            base_url: get("MEDUSA_MODEL_BASE_URL")?
                .trim_end_matches('/')
                .to_string(),
            api_key: get("MEDUSA_MODEL_API_KEY")?,
            model: get("MEDUSA_MODEL_NAME")?,
            timeout_secs,
            connect_timeout_secs,
            stream_idle_timeout_secs,
            session_key,
        })
    }
}

/// Any OpenAI-compatible `/chat/completions` endpoint (OpenAI, Azure, Ollama,
/// vLLM, user-run gateways, ...). Sends the [`ContextView`] as JSON and
/// parses the reply via [`parse_decision_text`].
pub struct OpenAiCompatibleProvider {
    config: OpenAiConfig,
    /// One pooled keep-alive client for the provider's whole lifetime:
    /// reused across every call, so a session pays DNS + TCP + TLS once,
    /// not once per model call (the old per-call agent is what surfaced
    /// `os error 10060` connect flakiness). reqwest auto-negotiates
    /// HTTP/2 where the gateway offers it.
    client: reqwest::blocking::Client,
    /// Per-session routing key override (see [`OpenAiConfig::session_key`]).
    session_key: Option<String>,
    /// Shared cancel flag (Stop button): the stream watchdog polls it so
    /// a wedged in-flight call is abandoned within ~250ms instead of
    /// burning the full overall budget. `None` when no handle is attached
    /// (tests, one-shot CLI usage).
    cancel: Option<Arc<AtomicBool>>,
}

/// Proxy configuration mirroring the old `ureq::AgentBuilder::
/// try_proxy_from_env`: `HTTPS_PROXY`/`HTTP_PROXY` (lowercase honored),
/// `ALL_PROXY` as fallback, `NO_PROXY` exclusions. Invalid URLs are
/// ignored (treated as unset) rather than failing client construction.
fn proxies_from_env() -> Vec<reqwest::Proxy> {
    fn get(keys: &[&str]) -> Option<String> {
        keys.iter()
            .filter_map(|k| std::env::var(k).ok())
            .map(|v| v.trim().to_string())
            .find(|v| !v.is_empty())
    }
    let mut out = Vec::new();
    if let Some(url) = get(&["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]) {
        if let Ok(p) = reqwest::Proxy::https(&url) {
            out.push(p.no_proxy(reqwest::NoProxy::from_env()));
        }
    }
    if let Some(url) = get(&["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"]) {
        if let Ok(p) = reqwest::Proxy::http(&url) {
            out.push(p.no_proxy(reqwest::NoProxy::from_env()));
        }
    }
    out
}

impl OpenAiCompatibleProvider {
    pub fn new(config: OpenAiConfig) -> Self {
        // Three separated budgets: short connect cap (dead endpoints fail
        // fast) at the client, generous overall backstop (healthy long
        // generations must never be cut short), and per-read idle
        // enforced by the stream reader itself (reqwest has no per-read
        // knob — `read_sse_stream` runs the reads on a worker thread and
        // watches the chunk channel with a timeout).
        let build = |proxied: bool| {
            let mut builder = reqwest::blocking::Client::builder()
                .connect_timeout(Duration::from_secs(config.connect_timeout_secs.max(1)))
                .timeout(Duration::from_secs(config.timeout_secs.max(1)))
                .pool_idle_timeout(Duration::from_secs(90))
                .tcp_nodelay(true);
            if proxied {
                for proxy in proxies_from_env() {
                    builder = builder.proxy(proxy);
                }
            }
            builder.build()
        };
        // Construction only fails on a broken TLS/provider setup; fall
        // back to a proxyless client before giving up, so a malformed
        // proxy URL degrades to direct rather than bricking the provider.
        let client = build(true).or_else(|_| build(false)).expect(
            "reqwest client construction must succeed without proxies",
        );
        Self {
            config,
            client,
            session_key: None,
            cancel: None,
        }
    }

    pub fn from_env() -> Result<Self, ModelError> {
        Ok(Self::new(OpenAiConfig::from_env()?))
    }

    /// Raw chat completion shared by [`ModelProvider::decide`] (JSON contract
    /// parsed by the caller) and [`ModelProvider::chat`] (free text).
    ///
    /// Streamed (SSE) over the provider's pooled keep-alive client: chunks
    /// flow during generation, so gateways/proxies never see an idle
    /// connection (the old blocking call is what died on intermediary idle
    /// timeouts) and per-read idle — not a total deadline — detects stalls.
    /// Respects `HTTP(S)_PROXY`/`NO_PROXY` from the environment.
    fn complete(&self, system: &str, user: &str) -> Result<String, ModelError> {
        self.complete_with_usage(system, user).map(|(content, _)| content)
    }

    /// [`complete`] plus the call's token usage. Uses the endpoint's
    /// `usage` block when present (the trailing `stream_options.
    /// include_usage` chunk for streams); otherwise falls back to a char/4
    /// estimate over the request body and reply (marked estimated).
    fn complete_with_usage(
        &self,
        system: &str,
        user: &str,
    ) -> Result<(String, UsageReport), ModelError> {
        let body = serde_json::json!({
            "model": self.config.model,
            "temperature": 0.2,
            "stream": true,
            "stream_options": {"include_usage": true},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        });
        self.send_and_parse(&body)
    }

    /// Transcript variant of [`Self::complete_with_usage`]: the cache-first
    /// wire format `[system] + [brief] + [transcript...] + [tail]`.
    fn complete_transcript(
        &self,
        system: &str,
        brief: &str,
        transcript: &[TranscriptMsg],
        tail: &str,
    ) -> Result<(String, UsageReport), ModelError> {
        let mut messages =
            Vec::with_capacity(transcript.len().saturating_add(3));
        messages.push(serde_json::json!({"role": "system", "content": system}));
        messages.extend(render_chat_messages(brief, transcript, tail));
        if messages.len() == 1 {
            return Err(ModelError::BadResponse("no messages to send".into()));
        }
        let body = serde_json::json!({
            "model": self.config.model,
            "temperature": 0.2,
            "stream": true,
            "stream_options": {"include_usage": true},
            "messages": messages,
        });
        self.send_and_parse(&body)
    }

    /// Shared send/parse core for every OpenAI-compatible call: one pooled
    /// POST, status handling with the endpoint's error body, then the SSE
    /// stream path (with a legacy single-JSON fallback for endpoints that
    /// ignore `stream: true`).
    fn send_and_parse(
        &self,
        body: &serde_json::Value,
    ) -> Result<(String, UsageReport), ModelError> {
        let url = format!("{}/chat/completions", self.config.base_url);
        let prompt_chars = body.to_string().len();

        // One attempt per call: the drive loop owns retries (5 tries, each
        // bounded by this provider's per-call timeouts), so retrying here too
        // would multiply the wait and blow the step's time budget. Each
        // failure surfaces to the loop as one visible retry.
        let max_attempts = 1u32;
        let mut last_err: Option<String> = None;
        for attempt in 0..max_attempts {
            let mut req_builder = self
                .client
                .post(&url)
                .header("Authorization", format!("Bearer {}", self.config.api_key))
                .header("Content-Type", "application/json")
                .header("Accept", "text/event-stream, application/json");
            // Sticky-routing affinity where the gateway honors it. The key
            // is restricted to header-safe chars so a hostile env value
            // can never break request construction.
            let session_key = self
                .session_key
                .as_deref()
                .or(self.config.session_key.as_deref())
                .filter(|k| {
                    !k.is_empty()
                        && k.chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                });
            if let Some(key) = session_key {
                req_builder = req_builder.header("X-Cipher-Session", key);
            }
            let resp = req_builder.json(body).send();
            match resp {
                Ok(r) => {
                    let status = r.status();
                    if !status.is_success() {
                        // A bare "status code 400" never says WHICH field was
                        // rejected, so attach the endpoint's own error body
                        // (Anthropic returns `{"error":{"message":...}}`).
                        // The "status code NNN" prefix is kept verbatim:
                        // `is_transient_transport` keys its retries off it.
                        // A `Retry-After` response header (429/503) is
                        // captured as a machine-readable token the drive
                        // loop honors (capped) instead of its own backoff.
                        let retry_after = r
                            .headers()
                            .get(reqwest::header::RETRY_AFTER)
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.trim().parse::<u64>().ok())
                            .map(|n| format!(" [retry_after={n}s]"))
                            .unwrap_or_default();
                        let bytes = r.bytes().unwrap_or_default();
                        let detail = error_snippet(&String::from_utf8_lossy(&bytes));
                        let msg = if detail.trim().is_empty() {
                            format!("{url}: status code {}{retry_after}", status.as_u16())
                        } else {
                            format!("{url}: status code {}: {detail}{retry_after}", status.as_u16())
                        };
                        // Retry only transient transport errors (timeouts,
                        // connect failures like `os error 10060`, 429/5xx).
                        // Anything else surfaces via the outer path.
                        let transient = is_transient_transport(&msg);
                        last_err = Some(msg.clone());
                        if !transient || attempt + 1 >= max_attempts {
                            return Err(ModelError::Transport(msg));
                        }
                        continue;
                    }
                    let is_stream = r
                        .headers()
                        .get(reqwest::header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .map(|ct| ct.contains("text/event-stream"))
                        .unwrap_or(false);
                    if is_stream {
                        return read_sse_stream(
                            r,
                            prompt_chars,
                            Duration::from_secs(self.config.stream_idle_timeout_secs.max(1)),
                            Duration::from_secs(self.config.timeout_secs.max(1)),
                            self.cancel.as_deref(),
                        );
                    }
                    // The endpoint ignored `stream: true` and answered with
                    // one JSON body: parse it the legacy way.
                    return read_json_body(r, &url, prompt_chars);
                }
                Err(e) => {
                    let msg = e.to_string();
                    let transient = is_transient_transport(&msg);
                    last_err = Some(msg.clone());
                    if !transient || attempt + 1 >= max_attempts {
                        return Err(ModelError::Transport(msg));
                    }
                    // Exponential backoff: 800ms, 1600ms, 3200ms (jitter-free
                    // to keep tests deterministic; production still sleeps).
                    let backoff_ms = 800u64 * (1u64 << attempt);
                    std::thread::sleep(std::time::Duration::from_millis(backoff_ms));
                    continue;
                }
            }
        }
        Err(ModelError::Transport(
            last_err.unwrap_or_else(|| "unknown transport error".into()),
        ))
    }
}

/// Legacy non-streamed reply parse: the endpoint answered `stream: true`
/// with a single JSON body. Same contract as the stream path — content
/// plus usage, char/4 estimate when the endpoint omits it.
fn read_json_body(
    resp: reqwest::blocking::Response,
    url: &str,
    prompt_chars: usize,
) -> Result<(String, UsageReport), ModelError> {
    let json: serde_json::Value = resp
        .json()
        .map_err(|e| ModelError::BadResponse(format!("non-JSON reply from {url}: {e}")))?;
    let content = json
        .pointer("/choices/0/message/content")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            ModelError::BadResponse("missing choices[0].message.content".into())
        })?;
    Ok((content.clone(), usage_from(&json.get("usage"), prompt_chars, &content)))
}

/// Shared usage extraction: the endpoint's `usage` block when present and
/// non-empty, else the char/4 estimate (marked estimated) so the context
/// meter never reads zero on a real call.
fn usage_from(
    usage: &Option<&serde_json::Value>,
    prompt_chars: usize,
    content: &str,
) -> UsageReport {
    let report = usage.and_then(|u| {
        let num = |k: &str| u.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
        Some(UsageReport {
            prompt_tokens: num("prompt_tokens"),
            completion_tokens: num("completion_tokens"),
            total_tokens: num("total_tokens"),
            cached_tokens: u
                .get("prompt_tokens_details")
                .and_then(|d| d.get("cached_tokens"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            estimated: false,
        })
    });
    usage_or_estimate(report, prompt_chars, content)
}

/// [`usage_from`] over an already-built report (the SSE path accumulates
/// usage from the trailing `include_usage` chunk).
fn usage_or_estimate(
    report: Option<UsageReport>,
    prompt_chars: usize,
    content: &str,
) -> UsageReport {
    match report {
        // A present-but-empty usage block is no better than no block.
        Some(r) if r.total_tokens > 0 => r,
        _ => UsageReport::estimate(prompt_chars, content.len()),
    }
}

/// One accumulated SSE `data:` payload applied to the in-progress reply.
/// Pure (no IO) so the line-splitting behavior is unit-testable: `content`
/// grows from `choices[0].delta.content` (tolerating `message.content`
/// from non-delta servers), `usage` is captured from the trailing
/// `include_usage` chunk, and an `{"error": ...}` payload aborts the call.
/// Returns `true` when the stream terminator (`[DONE]`) was seen.
fn apply_sse_payload(
    payload: &str,
    content: &mut String,
    usage: &mut Option<UsageReport>,
) -> Result<bool, ModelError> {
    if payload == "[DONE]" {
        return Ok(true);
    }
    let json: serde_json::Value = match serde_json::from_str(payload) {
        Ok(v) => v,
        // Keep-alive comments or vendor extensions ride `data:` lines too;
        // unparseable lines are skipped, not fatal.
        Err(_) => return Ok(false),
    };
    if let Some(err) = json.get("error") {
        let detail: String = err
            .get("message")
            .and_then(|m| m.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| error_snippet(&err.to_string()));
        return Err(ModelError::Transport(format!("stream error: {detail}")));
    }
    if let Some(choice) = json.pointer("/choices/0") {
        if let Some(delta) = choice
            .pointer("/delta/content")
            .or_else(|| choice.pointer("/message/content"))
            .and_then(|v| v.as_str())
        {
            content.push_str(delta);
        }
    }
    if let Some(u) = json.get("usage") {
        let num = |k: &str| u.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
        *usage = Some(UsageReport {
            prompt_tokens: num("prompt_tokens"),
            completion_tokens: num("completion_tokens"),
            total_tokens: num("total_tokens"),
            cached_tokens: u
                .get("prompt_tokens_details")
                .and_then(|d| d.get("cached_tokens"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            estimated: false,
        });
    }
    Ok(false)
}

/// Accumulate an OpenAI-style SSE stream into the full reply text plus
/// usage. The main loop runs a unified 250ms-poll watchdog over a reader
/// thread feeding a channel, enforcing three budgets:
///
/// - **cancel** (Stop button): checked every poll — a wedged call is
///   abandoned within ~250ms as [`ModelError::Cancelled`], instead of
///   burning the overall budget while the UI already stood down.
/// - **per-read idle**: no chunk for `idle` → "stream stalled". Resets
///   on every received chunk, so healthy long generations pass through.
/// - **overall**: total wall-clock backstop → "exceeded overall budget".
///
/// Chunk boundaries can split a line anywhere, so a partial trailing
/// line is buffered, not parsed. When the watchdog returns early, the
/// detached reader thread exits on its next send failure (receiver
/// dropped) or at the client's own timeout — it never outlives the call
/// by more than one in-flight read and holds no session state.
fn read_sse_stream(
    resp: reqwest::blocking::Response,
    prompt_chars: usize,
    idle: Duration,
    overall: Duration,
    cancel: Option<&AtomicBool>,
) -> Result<(String, UsageReport), ModelError> {
    let (tx, rx) = std::sync::mpsc::channel::<Result<Option<Vec<u8>>, String>>();
    // The worker owns the response and exits on EOF, read error, or a
    // dropped receiver (caller gave up — cancellation or watchdog) — no
    // orphaned thread outlives the call by more than the in-flight read.
    std::thread::spawn(move || {
        let mut resp = resp;
        let mut buf = [0u8; 8192];
        loop {
            match std::io::Read::read(&mut resp, &mut buf) {
                Ok(0) => {
                    let _ = tx.send(Ok(None));
                    break;
                }
                Ok(n) => {
                    if tx.send(Ok(Some(buf[..n].to_vec()))).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(e.to_string()));
                    break;
                }
            }
        }
    });
    const POLL: Duration = Duration::from_millis(250);
    let start = std::time::Instant::now();
    let mut last_chunk = std::time::Instant::now();
    let mut content = String::new();
    let mut usage: Option<UsageReport> = None;
    let mut leftover: Vec<u8> = Vec::new();
    'outer: loop {
        if let Some(flag) = cancel {
            if flag.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(ModelError::Cancelled);
            }
        }
        if start.elapsed() >= overall {
            return Err(ModelError::Transport(format!(
                "stream exceeded overall budget of {}s",
                overall.as_secs()
            )));
        }
        if last_chunk.elapsed() >= idle {
            return Err(ModelError::Transport(format!(
                "stream stalled: no data for {}s",
                idle.as_secs()
            )));
        }
        // Wake at the poll cadence even with no data: cancel/overall/idle
        // all stay live between chunks. A real chunk short-circuits.
        match rx.recv_timeout(POLL) {
            Ok(Ok(Some(bytes))) => {
                last_chunk = std::time::Instant::now();
                leftover.extend_from_slice(&bytes);
            }
            // Clean EOF: deliver whatever accumulated (possibly nothing —
            // checked below). A missing terminator just means truncation.
            Ok(Ok(None)) => break,
            Ok(Err(e)) => return Err(ModelError::Transport(e)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            // Reader died without a terminal message (panic): treat as EOF
            // and let the empty-content check below decide.
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
        while let Some(pos) = leftover.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = leftover.drain(..=pos).collect();
            let line = String::from_utf8_lossy(&line);
            let line = line.trim_end_matches(['\r', '\n']);
            match line.strip_prefix("data:") {
                Some(p) => {
                    if apply_sse_payload(p.trim_start(), &mut content, &mut usage)? {
                        break 'outer;
                    }
                }
                // `: comment` keep-alives and blank lines carry nothing.
                None => continue,
            }
        }
    }
    if content.trim().is_empty() {
        return Err(ModelError::BadResponse("stream produced no content".into()));
    }
    Ok((content.clone(), usage_or_estimate(usage, prompt_chars, &content)))
}

/// Pull the human-readable reason out of an endpoint error body:
/// `{"error":{"message":...}}` (Anthropic), `{"message":...}`, or the
/// raw first 300 chars as a fallback. Never includes request data, so
/// no secrets can leak through it — only the endpoint's own words.
fn error_snippet(body: &str) -> String {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        for ptr in ["/error/message", "/message"] {
            if let Some(s) = v.pointer(ptr).and_then(|x| x.as_str()) {
                if !s.trim().is_empty() {
                    return s.chars().take(300).collect();
                }
            }
        }
    }
    body.chars().take(300).collect()
}

fn is_transient_transport(msg: &str) -> bool {    let m = msg.to_lowercase();
    // Windows connect timeout, ureq timeouts, and HTTP 429/5xx surfaced as
    // `Transport` by ureq (e.g. "status code 429", "status code 502").
    m.contains("10060")
        || m.contains("timed out")
        || m.contains("timeout")
        || m.contains("connection")
        || m.contains("temporarily")
        || m.contains("transport")
        || m.contains("network error")
        || m.contains("status code 429")
        || m.contains("status code 500")
        || m.contains("status code 502")
        || m.contains("status code 503")
        || m.contains("status code 504")
}

impl ModelProvider for OpenAiCompatibleProvider {
    fn name(&self) -> &str {
        "openai-compatible"
    }

    fn decide(&self, ctx: &ContextView) -> Result<Decision, ModelError> {
        let (content, _) =
            self.complete_transcript(SYSTEM_PROMPT, &ctx.brief, &ctx.transcript, &ctx.tail)?;
        with_reply_diagnostics(parse_decision_text(&content), &content)
    }

    /// [`decide`] with real usage numbers from the endpoint's `usage`
    /// block (char/4 estimate when the endpoint omits it). Drives the
    /// context meter and auto-compaction.
    fn decide_reported(&self, ctx: &ContextView) -> (Result<Decision, ModelError>, UsageReport) {
        match self.complete_transcript(SYSTEM_PROMPT, &ctx.brief, &ctx.transcript, &ctx.tail) {
            Ok((content, usage)) => (
                with_reply_diagnostics(parse_decision_text(&content), &content),
                usage,
            ),
            Err(e) => (
                Err(e),
                UsageReport::estimate(
                    transcript_wire_chars(SYSTEM_PROMPT, &ctx.brief, &ctx.transcript, &ctx.tail),
                    0,
                ),
            ),
        }
    }

    fn chat(&self, system: &str, user: &str) -> Result<String, ModelError> {
        self.complete(system, user)
    }

    /// Native-array override: the fork shares the parent's exact prefix
    /// (system + history), so the summarization request is a cache hit,
    /// not a full-price re-prefill.
    fn chat_messages(&self, system: &str, messages: &[serde_json::Value]) -> Result<String, ModelError> {
        let mut full = Vec::with_capacity(messages.len().saturating_add(1));
        full.push(serde_json::json!({"role": "system", "content": system}));
        full.extend(messages.iter().cloned());
        let body = serde_json::json!({
            "model": self.config.model,
            "temperature": 0.2,
            "stream": true,
            "stream_options": {"include_usage": true},
            "messages": full,
        });
        self.send_and_parse(&body).map(|(content, _)| content)
    }

    fn set_session_key(&mut self, key: String) {
        let clean = key.trim().to_string();
        self.session_key = if clean.is_empty() { None } else { Some(clean) };
    }

    /// Stop button: the stream watchdog polls this flag so a wedged
    /// in-flight call is abandoned within ~250ms (see
    /// [`read_sse_stream`]) instead of burning the full overall budget.
    fn set_cancel_flag(&mut self, flag: Arc<AtomicBool>) {
        self.cancel = Some(flag);
    }
}

/// Wire-size estimate for the transcript request (usage-estimate fallback
/// when the call fails before any usage arrives). Sums raw chars — the
/// same basis `UsageReport::estimate` has always used.
pub fn transcript_wire_chars(
    system: &str,
    brief: &str,
    transcript: &[TranscriptMsg],
    tail: &str,
) -> usize {
    system.len()
        + brief.len()
        + tail.len()
        + transcript
            .iter()
            .map(|m| m.role.len() + m.content.len())
            .sum::<usize>()
}

/// Class of LLM failure for retry pacing: slow burns (full-budget
/// timeouts, stalls, rate limits, 5xx) must NOT be hammered — the
/// endpoint is alive but struggling. Everything else (connect failures,
/// refusals, DNS, resets) fails fast and retries fast.
pub fn is_slow_llm_error(err: &str) -> bool {
    let e = err.to_lowercase();
    e.contains("timed out")
        || e.contains("timeout")
        || e.contains("stalled")
        || e.contains("overall budget")
        || e.contains("status code 429")
        || e.contains("status code 500")
        || e.contains("status code 502")
        || e.contains("status code 503")
        || e.contains("status code 504")
}

/// Backoff before a same-step LLM retry, in milliseconds. Fast class
/// (connection errors): fixed 100ms — the failure was instant, so the
/// retry is cheap. Slow class: exponential 2s → 10s cap — hammering a
/// struggling endpoint only extends the outage.
pub fn llm_retry_delay_ms(consecutive_errors: usize, err: &str) -> u64 {
    if !is_slow_llm_error(err) {
        return 100;
    }
    let shift = consecutive_errors.saturating_sub(1).min(3) as u32;
    (2000u64 << shift).min(10_000)
}

/// Consecutive slow-burn failures after which the drive loop gives up
/// early instead of riding out the full 5-try budget: two burned overall
/// budgets in a row means the endpoint is wedged, not flapping.
pub const LLM_MAX_SLOW_RETRIES: usize = 2;

/// Extract the `[retry_after=Ns]` token the provider appends to
/// rate-limit errors. `None` when absent or unparsable.
pub fn parse_retry_after_secs(err: &str) -> Option<u64> {
    let start = err.find("[retry_after=")? + "[retry_after=".len();
    let rest = &err[start..];
    let end = rest.find(']')?;
    rest[..end].trim_end_matches('s').parse::<u64>().ok()
}

/// Cap for a honored `Retry-After`: a hostile or buggy header must not
/// stall a step for hours (opencode caps at 15 minutes; a step budget
/// here is far tighter).
pub const LLM_MAX_RETRY_AFTER_SECS: u64 = 120;

/// Substitute `{{vault:key}}` references in tool options with vaulted
/// values, resolved out-of-band at execution time. Values never enter
/// prompts, traces (which only carry `sanitized_options`), or events —
/// the wire only ever sees key names. Unknown keys (or an unavailable
/// vault) fail like any other argument error: no step is consumed, the
/// model self-corrects from `last_error`. Strings without references
/// return unchanged.
pub fn substitute_vault_refs(
    options: &OptionSet,
    resolve: &dyn Fn(&str) -> Option<String>,
) -> Result<OptionSet, String> {
    let mut out = OptionSet::new();
    for (k, v) in options {
        let replaced = match v {
            OptionValue::Str(s) => OptionValue::Str(substitute_vault_refs_in_text(s, resolve)?),
            OptionValue::Num(n) => OptionValue::Num(*n),
            OptionValue::Bool(b) => OptionValue::Bool(*b),
            OptionValue::Map(m) => OptionValue::Map(
                m.iter()
                    .map(|(mk, mv)| {
                        substitute_vault_refs_in_text(mv, resolve).map(|rv| (mk.clone(), rv))
                    })
                    .collect::<Result<std::collections::BTreeMap<_, _>, _>>()?,
            ),
        };
        out.insert(k.clone(), replaced);
    }
    Ok(out)
}

/// True when any option string carries a `{{vault:…}}` reference.
pub fn options_contain_vault_refs(options: &OptionSet) -> bool {
    options.values().any(|v| match v {
        OptionValue::Str(s) => s.contains("{{vault:"),
        OptionValue::Map(m) => m.values().any(|s| s.contains("{{vault:")),
        OptionValue::Num(_) | OptionValue::Bool(_) => false,
    })
}

/// Text-level `{{vault:key}}` substitution shared by option strings and
/// file content. Each resolved value is registered with the trace
/// scrubber, so an injected secret can never land in a trace file even
/// where no key/Bearer/JWT pattern matches it.
pub fn substitute_vault_refs_in_text(
    text: &str,
    resolve: &dyn Fn(&str) -> Option<String>,
) -> Result<String, String> {
    const MARKER: &str = "{{vault:";
    if !text.contains(MARKER) {
        return Ok(text.to_string());
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find(MARKER) {
        out.push_str(&rest[..start]);
        let after = &rest[start + MARKER.len()..];
        match after.find("}}") {
            Some(end) => {
                let key = after[..end].trim();
                match resolve(key) {
                    Some(value) => {
                        crate::infra::trace::register_secret_for_scrubbing(&value);
                        out.push_str(&value);
                    }
                    None => {
                        return Err(format!(
                            "unknown vault key `{key}` — recall it first with vault_recall (keys only; values are injected at execution)"
                        ))
                    }
                }
                rest = &after[end + 2..];
            }
            // Unterminated marker: leave the remainder verbatim rather
            // than failing a legitimately brace-heavy argument.
            None => {
                out.push_str(&rest[start..]);
                rest = "";
                break;
            }
        }
    }
    out.push_str(rest);
    Ok(out)
}

// ---------------------------------------------------------------------------
// CLI provider (local harnesses: `claude -p`, `opencode run`, ...)
// ---------------------------------------------------------------------------

/// A local harness subprocess as a model: one one-shot invocation per
/// model call, prompt in, answer on stdout. The harness sees the exact
/// same content as an HTTP provider (system prompt + serialized view,
/// joined into one prompt string) and answers are parsed by the same
/// tolerant decision parser — only the envelope differs.
///
/// Spawned with an argv list, never a shell. Nonzero exits, spawn
/// failures, and timeouts surface as `Transport` errors, so the drive
/// loop retries and feeds them back exactly like HTTP failures.
/// Plain-text CLI output carries no token counts, so usage is always
/// the char/4 estimate (via the `decide_reported` default).
///
/// When `stdin_prompt` is set, the prompt travels on the harness's
/// standard input instead of argv — required for big prompts on
/// Windows, where command lines cap at ~32K chars and a full system
/// prompt + context makes the spawn itself fail with `os error 206`.
pub struct CliProvider {
    exe: String,
    args: Vec<String>,
    label: String,
    display_name: String,
    timeout: Duration,
    stdin_prompt: bool,
    executor: Arc<dyn ProcessExecutor>,
}

impl CliProvider {
    pub fn new(
        exe: String,
        args: Vec<String>,
        label: String,
        timeout_secs: u64,
        stdin_prompt: bool,
    ) -> Self {
        let display_name = format!("cli:{label}");
        Self {
            exe,
            args,
            label,
            display_name,
            timeout: Duration::from_secs(timeout_secs.max(1)),
            stdin_prompt,
            executor: Arc::new(LocalProcessExecutor::with_timeout(Duration::from_secs(
                timeout_secs.max(1),
            ))),
        }
    }

    #[cfg(test)]
    fn with_executor(
        exe: &str,
        args: Vec<String>,
        label: &str,
        executor: Arc<dyn ProcessExecutor>,
    ) -> Self {
        Self {
            exe: exe.to_string(),
            args,
            label: label.to_string(),
            display_name: format!("cli:{label}"),
            timeout: Duration::from_secs(30),
            stdin_prompt: false,
            executor,
        }
    }

    /// Test-only: route the prompt through the harness's stdin (any
    /// `{prompt}` slots are dropped from the fixed argv).
    #[cfg(test)]
    fn with_stdin_prompt(mut self) -> Self {
        self.stdin_prompt = true;
        self
    }

    /// Build the argv: every `"{prompt}"` occurrence is replaced; when no
    /// argument contains the placeholder, the prompt is appended last
    /// (positional-prompt harnesses like `opencode run <message>`).
    pub fn render_args(&self, prompt: &str) -> Vec<String> {
        if self.args.iter().any(|a| a.contains("{prompt}")) {
            self.args
                .iter()
                .map(|a| a.replace("{prompt}", prompt))
                .collect()
        } else {
            let mut out = self.args.clone();
            out.push(prompt.to_string());
            out
        }
    }

    fn invoke(&self, prompt: &str) -> Result<String, ModelError> {
        let out = if self.stdin_prompt {
            // Prompt bypasses argv entirely: `{prompt}` slots, if any,
            // are dropped from the fixed argv and the bytes go to the
            // harness's stdin.
            let argv: Vec<String> = self
                .args
                .iter()
                .filter(|a| !a.contains("{prompt}"))
                .cloned()
                .collect();
            self.executor
                .run_with_stdin(&self.exe, &argv, prompt.as_bytes(), self.timeout)
        } else {
            let argv = self.render_args(prompt);
            self.executor.run(&self.exe, &argv, self.timeout)
        };
        if out.timed_out {
            return Err(ModelError::Transport(format!(
                "cli model `{}` timed out after {}s",
                self.exe,
                self.timeout.as_secs()
            )));
        }
        if let Some(e) = out.error {
            return Err(ModelError::Transport(format!(
                "cli model `{}` failed to run: {e}",
                self.exe
            )));
        }
        if out.exit_code != 0 {
            // The harness's own stderr tail (auth failures, bad flags,
            // missing login) — the actionable part of the failure.
            let trimmed = out.stderr.trim();
            let snip: String = trimmed
                .chars()
                .rev()
                .take(500)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            return Err(ModelError::Transport(format!(
                "cli model `{}` exited {}: {}",
                self.exe, out.exit_code, snip
            )));
        }
        let text = out.stdout.trim().to_string();
        if text.is_empty() {
            return Err(ModelError::BadResponse(format!(
                "cli model `{}` returned empty output",
                self.exe
            )));
        }
        Ok(text)
    }
}

impl ModelProvider for CliProvider {
    fn name(&self) -> &str {
        &self.display_name
    }

    fn decide(&self, ctx: &ContextView) -> Result<Decision, ModelError> {
        let prompt = render_cli_prompt(SYSTEM_PROMPT, &ctx.brief, &ctx.transcript, &ctx.tail);
        let reply = self.invoke(&prompt)?;
        with_reply_diagnostics(parse_decision_text(&reply), &reply)
    }

    fn chat(&self, system: &str, user: &str) -> Result<String, ModelError> {
        self.invoke(&format!("{system}\n\n---\n\n{user}"))
    }

    fn set_cancel_flag(&mut self, flag: Arc<AtomicBool>) {
        // Rebuild the executor as a cancel-aware local spawn (same
        // timeout) so a Stop kills the harness subprocess mid-call. The
        // CLI harness is the one provider that blocks the turn on an
        // external process; HTTP providers return over the network and
        // need nothing here.
        self.executor =
            Arc::new(LocalProcessExecutor::with_timeout(self.timeout).with_cancel(flag));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::executor::ProcessOutput;

    #[test]
    fn parses_execute_hypothesis_finish() {
        let d = parse_decision_text(
            r#"... {"decision":"execute","capability":"network.port_scan","target":"10.0.0.1","reason":"open ports unknown"} ..."#,
        )
        .unwrap();
        assert_eq!(
            d,
            Decision::Execute {
                capability: "network.port_scan".into(),
                target: "10.0.0.1".into(),
                options: OptionSet::new(),
                reason: "open ports unknown".into(),
            }
        );
        let d = parse_decision_text(
            r#"{"decision":"hypothesis","statement":"BOLA?","confidence":"low"}"#,
        )
        .unwrap();
        assert!(matches!(d, Decision::CreateHypothesis { .. }));
        let d = parse_decision_text(r#"{"decision":"finish","reason":"done"}"#).unwrap();
        assert!(matches!(d, Decision::Finish { .. }));
    }

    #[test]
    fn action_summary_alias_parses_as_reason() {
        // The v2 system prompt names the execute preamble "action_summary";
        // either spelling must land in the user-facing reason.
        let d = parse_decision_text(
            r#"{"decision":"execute","capability":"network.port_scan","target":"10.0.0.1","options":{},"action_summary":"scanning for exposed services"}"#,
        )
        .unwrap();
        assert!(matches!(
            d,
            Decision::Execute { ref reason, .. } if reason == "scanning for exposed services"
        ));
    }

    #[test]
    fn narrate_decision_parses() {
        let d = parse_decision_text(
            r#"{"decision":"narrate","text":"Found exposed admin config at /rest/admin/application-configuration."}"#,
        )
        .unwrap();
        assert!(matches!(
            d,
            Decision::Narrate { ref text }
                if text.starts_with("Found exposed admin config")
        ));
        // Empty narrations are rejected like empty replies.
        assert!(parse_decision_text(r#"{"decision":"narrate","text":""}"#).is_err());
    }

    #[test]
    fn file_and_web_search_decisions_parse() {
        // file_read
        match parse_decision_text(
            r#"{"decision":"file_read","path":"bundle.js","action_summary":"read the app bundle"}"#,
        )
        .unwrap()
        {
            Decision::FileRead { path, grep, lines, reason } => {
                assert_eq!(path, "bundle.js");
                assert_eq!(grep, None);
                assert_eq!(lines, None);
                assert!(reason.contains("app bundle"));
            }
            other => panic!("expected FileRead, got {other:?}"),
        }
        // file_write
        match parse_decision_text(
            r#"{"decision":"file_write","path":"poc.py","content":"print('x')","action_summary":"write poc"}"#,
        )
        .unwrap()
        {
            Decision::FileWrite { path, content, .. } => {
                assert_eq!(path, "poc.py");
                assert_eq!(content, "print('x')");
            }
            other => panic!("expected FileWrite, got {other:?}"),
        }
        // Empty/absent fields are rejected.
        assert!(parse_decision_text(r#"{"decision":"file_read","path":""}"#).is_err());
        assert!(parse_decision_text(r#"{"decision":"file_read"}"#).is_err());
        // grep/lines are carried through
        match parse_decision_text(
            r#"{"decision":"file_read","path":"log.txt","grep":"admin","lines":200}"#,
        )
        .unwrap()
        {
            Decision::FileRead {
                path, grep, lines, ..
            } => {
                assert_eq!(path, "log.txt");
                assert_eq!(grep.as_deref(), Some("admin"));
                assert_eq!(lines, Some(200));
            }
            other => panic!("expected FileRead, got {other:?}"),
        }
        assert!(
            parse_decision_text(r#"{"decision":"file_write","path":"a.py","content":""}"#)
                .is_err()
        );
        // web_search
        match parse_decision_text(
            r#"{"decision":"web_search","query":"juice shop jwt"}"#,
        )
        .unwrap()
        {
            Decision::WebSearch { query, .. } => assert_eq!(query, "juice shop jwt"),
            other => panic!("expected WebSearch, got {other:?}"),
        }
    }

    #[test]
    fn parses_semantic_options_and_ignores_invented_fields() {
        // Valid scalar options are carried through; a model-invented
        // "provider" field has no representation and is simply ignored —
        // the runtime selects providers, never the model.
        let d = parse_decision_text(
            r#"{"decision":"execute","capability":"network.port_scan","target":"10.0.0.1","provider":"naabu","options":{"ports":"80,443","intensity":"normal","depth":3},"reason":"r"}"#,
        )
        .unwrap();
        match d {
            Decision::Execute { options, .. } => {
                assert_eq!(
                    options.get("ports"),
                    Some(&OptionValue::Str("80,443".into()))
                );
                assert_eq!(
                    options.get("intensity"),
                    Some(&OptionValue::Str("normal".into()))
                );
                assert_eq!(options.get("depth"), Some(&OptionValue::Num(3.0)));
                assert!(!options.contains_key("provider"));
            }
            other => panic!("expected execute, got {other:?}"),
        }
    }

    #[test]
    fn rejects_non_scalar_option_values() {
        // Arrays/objects cannot smuggle structured payloads (flags lists,
        // nested commands) through the options field.
        let err = parse_decision_text(
            r#"{"decision":"execute","capability":"network.port_scan","target":"x","options":{"flags":["--privileged","-O"]}}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("flags"), "{err}");
    }

    #[test]
    fn parses_string_pair_objects_into_map_values() {
        // Structured options (e.g. headers) arrive as JSON objects of
        // string pairs; nested non-strings and arrays stay rejected.
        let d = parse_decision_text(
            r#"{"decision":"execute","capability":"http.request","target":"http://x/","options":{"headers":{"Authorization":"Bearer abc","Content-Type":"application/json"}},"reason":"r"}"#,
        )
        .unwrap();
        match d {
            Decision::Execute { options, .. } => match options.get("headers") {
                Some(OptionValue::Map(m)) => {
                    assert_eq!(m.get("Authorization").map(String::as_str), Some("Bearer abc"));
                    assert_eq!(
                        m.get("Content-Type").map(String::as_str),
                        Some("application/json")
                    );
                }
                other => panic!("expected Map headers, got {other:?}"),
            },
            other => panic!("expected execute, got {other:?}"),
        }
        let err = parse_decision_text(
            r#"{"decision":"execute","capability":"http.request","target":"x","options":{"headers":{"Authorization":{"nested":1}}}}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("headers"), "{err}");
        let err = parse_decision_text(
            r#"{"decision":"execute","capability":"http.request","target":"x","options":{"headers":null}}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("headers"), "{err}");
    }

    #[test]
    fn map_values_render_names_only_never_secrets() {
        // Display/render feed evidence strings and feedback: values must
        // never leak through them (this exact leak caused the JWT echo in
        // the observed incident).
        let mut m = std::collections::BTreeMap::new();
        m.insert("Authorization".to_string(), "Bearer eyJzZWNyZXQ".to_string());
        m.insert("Content-Type".to_string(), "application/json".to_string());
        let v = OptionValue::Map(m);
        let shown = v.to_string();
        assert!(shown.contains("Authorization"), "{shown}");
        assert!(shown.contains("Content-Type"), "{shown}");
        assert!(!shown.contains("eyJzZWNyZXQ"), "{shown}");
        assert_eq!(v.kind_name(), "an object of string pairs");
        assert!(!v.render().contains("eyJzZWNyZXQ"), "{shown}");
    }

    #[test]
    fn parses_reply_decision() {        let d = parse_decision_text(
            r#"{"decision":"reply","text":"Found 3 open ports. Want me to continue with service detection?"}"#,
        )
        .unwrap();
        assert_eq!(
            d,
            Decision::Reply {
                text: "Found 3 open ports. Want me to continue with service detection?".into()
            }
        );
        // Empty reply text is a bad response, not a silent no-op.
        assert!(parse_decision_text(r#"{"decision":"reply","text":"  "}"#).is_err());
    }

    #[test]
    fn rejects_garbage_and_unknown_kinds() {
        assert!(parse_decision_text("no json here").is_err());
        assert!(parse_decision_text(r#"{"decision":"nuke"}"#).is_err());
        assert!(parse_decision_text(r#"{"decision":"execute"}"#).is_err());
    }

    #[test]
    fn parses_finding_and_vault_decisions() {
        let d = parse_decision_text(
            r#"{"decision":"report_finding","severity":"high","title":"SQLi in login","target":"10.0.0.1","detail":"error-based"} "#,
        )
        .unwrap();
        assert_eq!(
            d,
            Decision::ReportFinding {
                severity: "High".into(),
                title: "SQLi in login".into(),
                target: "10.0.0.1".into(),
                detail: "error-based".into(),
            }
        );
        // Unknown severity degrades to Medium, never an error.
        let d = parse_decision_text(
            r#"{"decision":"report_finding","severity":"catastrophic","title":"X"}"#,
        )
        .unwrap();
        assert!(matches!(d, Decision::ReportFinding { severity, .. } if severity == "Medium"));
        let d = parse_decision_text(
            r#"{"decision":"update_finding","finding_id":3,"status":"confirmed"}"#,
        )
        .unwrap();
        assert_eq!(
            d,
            Decision::UpdateFinding {
                id: 3,
                status: "confirmed".into(),
                note: String::new(),
            }
        );
        assert!(parse_decision_text(r#"{"decision":"update_finding"}"#).is_err());
        let d = parse_decision_text(
            r#"{"decision":"vault_store","key":"db_password","value":"s3cr3t","kind":"password","source":"env"}"#,
        )
        .unwrap();
        assert!(matches!(d, Decision::VaultStore { .. }));
        assert!(parse_decision_text(r#"{"decision":"vault_store","key":"k"}"#).is_err());
        let d = parse_decision_text(r#"{"decision":"vault_recall","query":"db_password"}"#).unwrap();
        assert_eq!(
            d,
            Decision::VaultRecall {
                query: "db_password".into()
            }
        );
        assert!(parse_decision_text(r#"{"decision":"report_finding"}"#).is_err());
    }

    #[test]
    fn usage_estimate_scales_with_chars() {
        let r = UsageReport::estimate(4000, 400);
        assert!(r.estimated);
        assert_eq!(r.prompt_tokens, 1000);
        assert_eq!(r.completion_tokens, 100);
        assert_eq!(r.total_tokens, 1100);
    }

    #[test]
    fn error_snippet_extracts_endpoint_reason() {        let s = error_snippet(r#"{"type":"error","error":{"type":"invalid_request_error","message":"temperature may only be set to 1.0 when thinking is enabled"}}"#);
        assert!(s.contains("temperature may only be set to 1.0"));
        let s = error_snippet(r#"{"message":"model not found"}"#);
        assert_eq!(s, "model not found");
        // Non-JSON bodies pass through truncated.
        let s = error_snippet(&"x".repeat(500));
        assert_eq!(s.len(), 300);
        assert_eq!(error_snippet(""), "");
    }

    #[test]
    fn cli_render_args_substitutes_or_appends_prompt() {
        use crate::agent::executor::StubExecutor;
        let stub: Arc<dyn crate::agent::executor::ProcessExecutor> =
            Arc::new(StubExecutor::new());
        let p = CliProvider::with_executor(
            "opencode",
            vec!["run".into(), "{prompt}".into()],
            "opencode",
            stub,
        );
        assert_eq!(p.render_args("hi"), vec!["run".to_string(), "hi".to_string()]);
        let stub2: Arc<dyn crate::agent::executor::ProcessExecutor> =
            Arc::new(StubExecutor::new());
        let p2 = CliProvider::with_executor("opencode", vec!["run".into()], "opencode", stub2);
        // No placeholder: prompt appended last.
        assert_eq!(
            p2.render_args("hi"),
            vec!["run".to_string(), "hi".to_string()]
        );
        assert_eq!(p.name(), "cli:opencode");
    }

    #[test]
    fn cli_decide_parses_harness_stdout() {
        use crate::agent::executor::StubExecutor;
        let stub: Arc<dyn crate::agent::executor::ProcessExecutor> = Arc::new(
            StubExecutor::success("myharness", "thinking out loud\n{\"decision\":\"finish\",\"reason\":\"ok\"}\n"),
        );
        let p = CliProvider::with_executor("myharness", vec!["{prompt}".into()], "t", stub);
        // Leading prose tolerated, same as non-JSON-mode HTTP endpoints.
        let d = p
            .decide(&ContextView {
                target: "x".into(),
                step: 0,
                autonomous: false,
                conversation: vec![],
                available_capabilities: vec![],
                unavailable_count: 0,
                observations: vec![],
                recent_evidence: vec![],
                narrations: vec![],
                prior_actions: vec![],
                capability_schemas: vec![],
                last_error: None,
                recent_errors: vec![],
                findings: vec![],
                vault_keys: vec![],
                vault_values: vec![],
                context_note: None,
                attack_summary: vec![],
                family_progress: vec![],
                unknowns: vec![],
                completion_note: None,
                pending_narration: None,
                strategy_hint: None,
                ..Default::default()
            })
            .unwrap();
        assert!(matches!(d, Decision::Finish { .. }));
    }

    #[test]
    fn cli_failures_map_to_transport_or_bad_response() {
        use crate::agent::executor::{ProcessOutput, StubExecutor};
        // Unconfigured exe: spawn failure â†’ Transport (retried).
        let stub: Arc<dyn crate::agent::executor::ProcessExecutor> =
            Arc::new(StubExecutor::new());
        let p = CliProvider::with_executor("nope-missing", vec![], "t", stub);
        assert!(matches!(
            p.invoke("hi"),
            Err(ModelError::Transport(_))
        ));
        // Nonzero exit with stderr â†’ Transport carrying the tail.
        let stub: Arc<dyn crate::agent::executor::ProcessExecutor> = Arc::new(
            StubExecutor::new().with_output(
                "badcli",
                ProcessOutput {
                    exit_code: 1,
                    stdout: String::new(),
                    stderr: "auth failed: login required".into(),
                    timed_out: false,
                    error: None,
                },
            ),
        );
        let p = CliProvider::with_executor("badcli", vec![], "t", stub);
        match p.invoke("hi") {
            Err(ModelError::Transport(msg)) => assert!(msg.contains("login required")),
            other => panic!("expected Transport, got {other:?}"),
        }
        // Exit 0, empty stdout â†’ BadResponse (not retried as transport).
        let stub: Arc<dyn crate::agent::executor::ProcessExecutor> = Arc::new(
            StubExecutor::success("emptycli", "   "),
        );
        let p = CliProvider::with_executor("emptycli", vec![], "t", stub);
        assert!(matches!(
            p.invoke("hi"),
            Err(ModelError::BadResponse(_))
        ));
    }

    #[test]
    fn stub_replays_then_finishes() {
        let stub = StubProvider::finish_now();
        let ctx = ContextView {
            target: "x".into(),
            step: 0,
            autonomous: false,
            conversation: vec![],
            available_capabilities: vec![],
            unavailable_count: 0,
            observations: vec![],
            recent_evidence: vec![],
            narrations: vec![],
            prior_actions: vec![],
            capability_schemas: vec![],
            last_error: None,
            recent_errors: vec![],
            findings: vec![],
            vault_keys: vec![],
            vault_values: vec![],
            context_note: None,
            attack_summary: vec![],
            family_progress: vec![],
            unknowns: vec![],
            completion_note: None,
            pending_narration: None,
            strategy_hint: None,
            ..Default::default()
        };
        assert!(matches!(
            stub.decide(&ctx).unwrap(),
            Decision::Finish { .. }
        ));
    }

    #[test]
    fn config_trims_trailing_slashes_off_base_url() {
        // from_env is covered against fake environments in infra::config;
        // here we only assert pure construction behavior (no env access).
        let cfg = OpenAiConfig {
            base_url: "https://example.com/v1".into(),
            api_key: "k".into(),
            model: "m".into(),
            timeout_secs: 60,
            connect_timeout_secs: 5,
            stream_idle_timeout_secs: 300,
            session_key: None,
        };
        let p = OpenAiCompatibleProvider::new(cfg);
        assert_eq!(p.name(), "openai-compatible");
    }

    #[test]
    fn sse_payload_accumulates_delta_content_and_usage() {
        let mut content = String::new();
        let mut usage = None;
        let chunk = |c: &str| {
            serde_json::json!({"choices": [{"delta": {"content": c}}]})
                .to_string()
        };
        assert!(!apply_sse_payload(&chunk("Hello"), &mut content, &mut usage).unwrap());
        assert!(!apply_sse_payload(&chunk(" world"), &mut content, &mut usage).unwrap());
        assert_eq!(content, "Hello world");
        assert!(usage.is_none());
        // Trailing include_usage chunk (empty choices).
        assert!(!apply_sse_payload(
            r#"{"choices":[],"usage":{"prompt_tokens":100,"completion_tokens":10,"total_tokens":110}}"#,
            &mut content,
            &mut usage,
        )
        .unwrap());
        let u = usage.unwrap();
        assert_eq!((u.prompt_tokens, u.completion_tokens, u.total_tokens), (100, 10, 110));
        assert!(!u.estimated);
        assert!(apply_sse_payload("[DONE]", &mut content, &mut usage).unwrap());
    }

    #[test]
    fn sse_payload_tolerates_message_content_rejects_error_skips_garbage() {
        let mut content = String::new();
        let mut usage = None;
        // Non-delta servers put the text under message.content.
        assert!(!apply_sse_payload(
            r#"{"choices":[{"message":{"content":"abc"}}]}"#,
            &mut content,
            &mut usage,
        )
        .unwrap());
        assert_eq!(content, "abc");
        // Keep-alive comments or vendor extensions are skipped, not fatal.
        assert!(!apply_sse_payload("not json", &mut content, &mut usage).unwrap());
        assert_eq!(content, "abc");
        // An error payload aborts the call as Transport (retryable).
        let err = apply_sse_payload(
            r#"{"error":{"message":"overloaded"}}"#,
            &mut content,
            &mut usage,
        )
        .unwrap_err();
        assert!(
            matches!(err, ModelError::Transport(ref m) if m.contains("overloaded")),
            "was: {err:?}"
        );
    }

    /// Serve one canned HTTP response on localhost; returns the base URL.
    /// The body goes out in `piece`-byte writes so the client's chunk
    /// boundaries split SSE lines mid-line.
    #[cfg(test)]
    fn serve_canned(headers: &str, body: &[u8], piece: usize) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = body.to_vec();
        let headers = headers.to_string();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .ok();
            // Consume the request: headers, then exactly Content-Length bytes.
            let mut req = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = stream.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..n]);
                if let Some(end) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                    let hdr = String::from_utf8_lossy(&req[..end]);
                    let len = hdr
                        .lines()
                        .filter_map(|l| l.split_once(':'))
                        .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
                        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    let mut remaining = len.saturating_sub(req.len() - (end + 4));
                    while remaining > 0 {
                        let n = stream.read(&mut buf).unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        remaining = remaining.saturating_sub(n);
                    }
                    break;
                }
            }
            let head = format!(
                "HTTP/1.1 200 OK\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(head.as_bytes()).unwrap();
            for part in body.chunks(piece.max(1)) {
                stream.write_all(part).unwrap();
                stream.flush().unwrap();
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        });
        format!("http://{addr}")
    }

    #[test]
    fn sse_stream_parses_split_chunks_end_to_end() {
        let chunks = [
            serde_json::json!({"choices": [{"delta": {"content": "{\"decision\": "}}]}),
            serde_json::json!({"choices": [{"delta": {"content": "\"finish\"}"}}]}),
            serde_json::json!({"choices": [], "usage": {"prompt_tokens": 100, "completion_tokens": 10, "total_tokens": 110}}),
        ];
        let mut sse = String::from(": keep-alive\n\n");
        for c in &chunks {
            sse.push_str("data: ");
            sse.push_str(&c.to_string());
            sse.push_str("\n\n");
        }
        sse.push_str("data: [DONE]\n\n");
        let url = serve_canned("Content-Type: text/event-stream\r\n", sse.as_bytes(), 7);
        // Bare client (no proxies): proxy env on the dev machine must not
        // route localhost through a gateway in tests.
        let client = reqwest::blocking::Client::builder().build().unwrap();
        let resp = client
            .post(format!("{url}/chat/completions"))
            .body("{}")
            .send()
            .unwrap();
        let (content, usage) =
            read_sse_stream(resp, 1000, Duration::from_secs(10), Duration::from_secs(30), None)
                .unwrap();
        assert_eq!(content, "{\"decision\": \"finish\"}");
        assert_eq!(usage.total_tokens, 110);
        assert!(!usage.estimated);
    }

    #[test]
    fn non_stream_json_body_still_parses() {
        let body = serde_json::json!({
            "choices": [{"message": {"content": "hi"}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 1, "total_tokens": 6},
        })
        .to_string();
        let url = serve_canned("Content-Type: application/json\r\n", body.as_bytes(), 4096);
        let client = reqwest::blocking::Client::builder().build().unwrap();
        let resp = client
            .post(format!("{url}/chat/completions"))
            .body("{}")
            .send()
            .unwrap();
        let (content, usage) = read_json_body(resp, &url, 500).unwrap();
        assert_eq!(content, "hi");
        assert_eq!(usage.total_tokens, 6);
        assert!(!usage.estimated);
    }

    #[test]
    fn stalled_stream_fails_on_idle_timeout() {
        use std::io::{Read, Write};
        // Server sends headers claiming a body, then goes silent.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let mut req = Vec::new();
            loop {
                let n = stream.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    return;
                }
                req.extend_from_slice(&buf[..n]);
                if req.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            stream.flush().unwrap();
            // Silent longer than the test's idle budget, then close.
            std::thread::sleep(std::time::Duration::from_secs(3));
        });
        let client = reqwest::blocking::Client::builder().build().unwrap();
        let resp = client
            .post(format!("http://{addr}/chat/completions"))
            .body("{}")
            .send()
            .unwrap();
        let err =
            read_sse_stream(resp, 0, Duration::from_secs(1), Duration::from_secs(30), None)
                .unwrap_err();
        assert!(
            matches!(err, ModelError::Transport(ref m) if m.contains("stalled")),
            "was: {err:?}"
        );
    }

    #[test]
    fn cancelled_stream_abandons_promptly() {
        use std::io::{Read, Write};
        use std::sync::atomic::Ordering;
        // Server sends headers + one data chunk, then goes silent — the
        // wedged-call shape. Stop is pressed shortly after: the watchdog
        // must abandon the call within the poll cadence, far ahead of the
        // idle (10s) and overall (60s) budgets.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let mut req = Vec::new();
            loop {
                let n = stream.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    return;
                }
                req.extend_from_slice(&buf[..n]);
                if req.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n";
            stream.write_all(head.as_bytes()).unwrap();
            stream.write_all(b"data: {\"choices\":[]}\n\n").unwrap();
            stream.flush().unwrap();
            // Silent from here on.
            std::thread::sleep(std::time::Duration::from_secs(15));
        });
        let cancel = Arc::new(AtomicBool::new(false));
        cancel.store(false, Ordering::SeqCst);
        let setter = Arc::clone(&cancel);
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(400));
            setter.store(true, Ordering::SeqCst);
        });
        let client = reqwest::blocking::Client::builder().build().unwrap();
        let resp = client
            .post(format!("http://{addr}/chat/completions"))
            .body("{}")
            .send()
            .unwrap();
        let t0 = std::time::Instant::now();
        let err = read_sse_stream(
            resp,
            0,
            Duration::from_secs(10),
            Duration::from_secs(60),
            Some(&cancel),
        )
        .unwrap_err();
        assert!(matches!(err, ModelError::Cancelled), "was: {err:?}");
        // Abandoned within ~1s of the press (250ms poll + slack) — not
        // the 10s idle, not the 60s overall.
        assert!(
            t0.elapsed() < Duration::from_secs(3),
            "cancel took {:?}",
            t0.elapsed()
        );
    }

    fn sample_transcript() -> Vec<TranscriptMsg> {
        vec![
            TranscriptMsg::user("hello".into()),
            TranscriptMsg::assistant("{\"decision\":\"finish\",\"reason\":\"ok\"}".into()),
        ]
    }

    #[test]
    fn wire_request_is_byte_stable_and_prefix_monotonic() {
        // Same inputs → byte-identical wire JSON (the cache-hit property).
        let a = serde_json::to_string(&render_chat_messages("brief", &sample_transcript(), "tail")).unwrap();
        let b = serde_json::to_string(&render_chat_messages("brief", &sample_transcript(), "tail")).unwrap();
        assert_eq!(a, b);
        // Appending extends the array: step N+1 starts with step N verbatim.
        let mut grown = sample_transcript();
        grown.push(TranscriptMsg::user("next tool result".into()));
        let c = render_chat_messages("brief", &grown, "tail2");
        let a_val: Vec<serde_json::Value> = serde_json::from_str(&a).unwrap();
        assert_eq!(&c[..a_val.len() - 1], &a_val[..a_val.len() - 1]);
        // …all but the regenerated tail, which is the one message allowed
        // to change (last position in both arrays).
        assert_eq!(c[c.len() - 1].get("content").and_then(|v| v.as_str()), Some("tail2"));
    }

    #[test]
    fn render_skips_blanks_and_normalizes_roles() {
        let msgs = render_chat_messages(
            "  ",
            &[
                TranscriptMsg { role: "assistant".into(), content: "a".into() },
                TranscriptMsg { role: "tool".into(), content: "t".into() },
                TranscriptMsg { role: "user".into(), content: "   ".into() },
            ],
            "",
        );
        let roles: Vec<&str> = msgs
            .iter()
            .map(|m| m.get("role").and_then(|r| r.as_str()).unwrap())
            .collect();
        assert_eq!(roles, vec!["assistant", "user"]);
    }

    #[test]
    fn decision_rendering_never_carries_secrets() {
        // vault_store keeps key+kind only.
        let d = Decision::VaultStore {
            key: "db_password".into(),
            value: "s3cr3t-value".into(),
            kind: "password".into(),
            source: "env".into(),
        };
        let rendered = render_decision_for_transcript(&d);
        assert!(rendered.contains("db_password"));
        assert!(!rendered.contains("s3cr3t-value"), "got: {rendered}");
        // execute drops options entirely (mirrors prior_actions).
        let mut options = OptionSet::new();
        options.insert("password".into(), OptionValue::Str("hunter2-hunter".into()));
        let d = Decision::Execute {
            capability: "x".into(),
            target: "t".into(),
            options,
            reason: "try it".into(),
        };
        let rendered = render_decision_for_transcript(&d);
        assert!(!rendered.contains("hunter2-hunter"), "got: {rendered}");
        assert!(rendered.contains("action_summary"));
        // file_write drops content.
        let d = Decision::FileWrite {
            path: "poc.txt".into(),
            content: "SECRET_BLOB_abc123".into(),
            reason: "poc".into(),
        };
        let rendered = render_decision_for_transcript(&d);
        assert!(!rendered.contains("SECRET_BLOB_abc123"), "got: {rendered}");
        // reply/narrate replay as natural text.
        let d = Decision::Reply { text: "done here".into() };
        assert_eq!(render_decision_for_transcript(&d), "done here");
    }

    #[test]
    fn vault_substitution_resolves_maps_and_reports_unknowns() {
        let resolve = |k: &str| match k {
            "db_password" => Some("s3cr3t-value".to_string()),
            _ => None,
        };
        let mut options = OptionSet::new();
        options.insert("user".into(), OptionValue::Str("admin".into()));
        options.insert(
            "password".into(),
            OptionValue::Str("prefix-{{vault:db_password}}-suffix".into()),
        );
        let mut headers = std::collections::BTreeMap::new();
        headers.insert("X-Key".into(), "{{vault:db_password}}".into());
        options.insert("headers".into(), OptionValue::Map(headers));
        options.insert("count".into(), OptionValue::Num(3.0));
        let out = substitute_vault_refs(&options, &resolve).unwrap();
        assert_eq!(
            out.get("password"),
            Some(&OptionValue::Str("prefix-s3cr3t-value-suffix".into()))
        );
        assert_eq!(out.get("user"), Some(&OptionValue::Str("admin".into())));
        match out.get("headers") {
            Some(OptionValue::Map(m)) => {
                assert_eq!(m.get("X-Key").map(String::as_str), Some("s3cr3t-value"))
            }
            other => panic!("expected map, got {other:?}"),
        }
        // Unknown keys fail with a actionable message; no refs = unchanged.
        let mut bad = OptionSet::new();
        bad.insert("p".into(), OptionValue::Str("{{vault:nope}}".into()));
        let err = substitute_vault_refs(&bad, &resolve).unwrap_err();
        assert!(err.contains("nope") && err.contains("vault_recall"), "got: {err}");
        let mut plain = OptionSet::new();
        plain.insert("a".into(), OptionValue::Str("b {{" .into()));
        assert_eq!(substitute_vault_refs(&plain, &resolve).unwrap(), plain);
        assert!(!options_contain_vault_refs(&plain));
        assert!(options_contain_vault_refs(&bad));
    }

    #[test]
    fn retry_pacing_fast_errors_slow_burns() {
        // Connection-class failures retry in 100ms (fail fast, retry fast).
        assert_eq!(llm_retry_delay_ms(1, "os error 10060"), 100);
        assert_eq!(llm_retry_delay_ms(4, "connection refused"), 100);
        assert_eq!(llm_retry_delay_ms(2, "dns lookup failed"), 100);
        assert!(!is_slow_llm_error("connection reset by peer"));
        // Slow burns back off exponentially, capped at 10s.
        assert_eq!(llm_retry_delay_ms(1, "operation timed out"), 2000);
        assert_eq!(llm_retry_delay_ms(2, "stream stalled: no data for 300s"), 4000);
        assert_eq!(llm_retry_delay_ms(3, "HTTP status code 503"), 8000);
        assert_eq!(llm_retry_delay_ms(9, "status code 429"), 10_000);
        assert!(is_slow_llm_error("stream exceeded overall budget of 600s"));
        // Retry-After token parsing.
        assert_eq!(
            parse_retry_after_secs("https://x/v1: status code 429: busy [retry_after=17s]"),
            Some(17)
        );
        assert_eq!(parse_retry_after_secs("plain transport error"), None);
        assert_eq!(parse_retry_after_secs("oops [retry_after=bogus]"), None);
    }

    #[test]
    fn doubled_braces_parse_after_one_layer_stripped() {
        // Templating habit: the whole object wrapped in `{{ ... }}`.
        let d = parse_decision_text("{{\"decision\":\"finish\",\"reason\":\"ok\"}}").unwrap();
        assert!(matches!(d, Decision::Finish { .. }));
        // Nested objects still work after the strip.
        let d = parse_decision_text("{{\"decision\":\"execute\",\"capability\":\"c\",\"target\":\"t\",\"options\":{},\"reason\":\"r\"}}")
            .unwrap();
        assert!(matches!(d, Decision::Execute { .. }));
        // Bare `{{}}` stays an error (missing decision field), not a panic.
        assert!(parse_decision_text("{{}}").is_err());
    }

    #[test]
    fn unparseable_reply_diagnostics_distinguish_modes_without_content() {
        // Pure prose: no braces at all.
        assert_eq!(
            describe_unparseable_reply("I cannot help with that request"),
            "31 chars, 0 '{', 0 '}'"
        );
        // Truncated JSON: opens without closes.
        assert_eq!(
            describe_unparseable_reply("{\"decision\": \"exec"),
            "18 chars, 1 '{', 0 '}'"
        );
        // Enrichment keeps successes untouched and never embeds content
        // (a failed reply can carry model-authored secrets).
        let secret = "s3cr3t-value";
        let err = with_reply_diagnostics(
            parse_decision_text("not json"),
            &format!("leaks {secret} here"),
        )
        .unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("no JSON object found"), "got: {msg}");
        assert!(msg.contains("0 '{'"), "got: {msg}");
        assert!(!msg.contains(secret), "secret leaked: {msg}");
        assert!(with_reply_diagnostics(
            Ok(Decision::Finish { reason: "x".into() }),
            "anything"
        )
        .is_ok());
    }

    #[test]
    fn usage_parses_cached_tokens_and_hit_rate() {        let json = serde_json::json!({
            "prompt_tokens": 1000,
            "completion_tokens": 50,
            "total_tokens": 1050,
            "prompt_tokens_details": {"cached_tokens": 900},
        });
        let report = usage_from(&Some(&json), 4000, "reply");
        assert_eq!(report.cached_tokens, 900);
        assert!(!report.estimated);
        assert_eq!(report.cache_hit_rate(), Some(0.9));
        // Absent details → zero cached, no rate on estimates.
        let json = serde_json::json!({"prompt_tokens": 10, "total_tokens": 10});
        let report = usage_from(&Some(&json), 40, "r");
        assert_eq!(report.cached_tokens, 0);
        assert_eq!(UsageReport::estimate(40, 4).cache_hit_rate(), None);
    }

    /// Test double recording the full invocation including stdin bytes,
    /// for proving prompt delivery via `run_with_stdin`.
    struct StdinRecorder {
        calls: std::sync::Mutex<Vec<(String, Vec<String>, Vec<u8>)>>,
        output: ProcessOutput,
    }

    impl StdinRecorder {
        fn succeeding(output: &str) -> Self {
            Self {
                calls: std::sync::Mutex::new(Vec::new()),
                output: ProcessOutput {
                    exit_code: 0,
                    stdout: output.to_string(),
                    stderr: String::new(),
                    timed_out: false,
                    error: None,
                },
            }
        }
    }

    impl ProcessExecutor for StdinRecorder {
        fn run(&self, exe: &str, args: &[String], _timeout: Duration) -> ProcessOutput {
            self.calls
                .lock()
                .unwrap()
                .push((exe.to_string(), args.to_vec(), Vec::new()));
            self.output.clone()
        }

        fn run_with_stdin(
            &self,
            exe: &str,
            args: &[String],
            stdin: &[u8],
            _timeout: Duration,
        ) -> ProcessOutput {
            self.calls
                .lock()
                .unwrap()
                .push((exe.to_string(), args.to_vec(), stdin.to_vec()));
            self.output.clone()
        }
    }

    #[test]
    fn stdin_prompt_sends_bytes_not_argv() {
        let rec = Arc::new(StdinRecorder::succeeding(
            "{\"decision\":\"finish\",\"reason\":\"ok\"}",
        ));
        let p = CliProvider::with_executor(
            "opencode",
            vec!["run".into(), "{prompt}".into()],
            "opencode",
            rec.clone(),
        )
        .with_stdin_prompt();
        let out = p.invoke("hello-prompt").unwrap();
        assert_eq!(out, "{\"decision\":\"finish\",\"reason\":\"ok\"}");
        let calls = rec.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (exe, argv, stdin) = &calls[0];
        assert_eq!(exe, "opencode");
        // `{prompt}` slot dropped from argv; prompt rides on stdin.
        assert_eq!(argv, &vec!["run".to_string()]);
        assert_eq!(stdin, b"hello-prompt");
    }

    #[test]
    #[ignore = "live: spawns the real opencode harness (one model call)"]
    fn cli_provider_stdin_prompt_reaches_harness_end_to_end() {
        let p = CliProvider::new(
            "opencode".to_string(),
            vec!["run".to_string()],
            "opencode".to_string(),
            300,
            true,
        );
        let out = p
            .chat("system", "Reply with exactly: PONG")
            .expect("harness invocation failed");
        assert!(out.contains("PONG"), "unexpected harness output: {out:?}");
    }
}
