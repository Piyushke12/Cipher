//! Per-session debug trace: every LLM call, tool invocation, decision,
//! state mutation and harness reply — one JSON object per line.
//!
//! Complements the user-facing session transcript (`sessions.rs`): the
//! transcript records *what happened*; the trace records *with what exact
//! bytes and what the model saw*. Same crash-safety (append + flush,
//! malformed tail lines skipped on read), same id validation.
//!
//! Secrets are redacted at WRITE time by [`scrub_value`]/[`scrub_text`]:
//! header names and option keys are kept, values are dropped. A trace file
//! must never become a credential store.

use std::cell::RefCell;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::cache::state_dir;

/// Keep per-file growth bounded: on open past this size, rewrite the tail.
pub const TRACE_MAX_BYTES: u64 = 5_000_000;
/// Bytes of tail kept on shrink.
const TRACE_KEEP_BYTES: u64 = 4_000_000;
/// Per-string cap after scrubbing.
pub const TRACE_STR_CAP: usize = 20_000;

/// ALL trace tags, CAPITAL LETTERS only (`AREA.EVENT`). Every
/// instrumentation site uses one of these consts — greppable, filterable,
/// and enforced by [`tag_format`] test.
pub mod tag {
    // Session / worker lifecycle.
    pub const SESSION_MESSAGE_RECEIVED: &str = "SESSION.MESSAGE_RECEIVED";
    pub const SESSION_WORKER_START: &str = "SESSION.WORKER_START";
    pub const SESSION_REPLAYED: &str = "SESSION.REPLAYED";
    pub const SESSION_TURN_START: &str = "SESSION.TURN_START";
    pub const SESSION_CANCELLED: &str = "SESSION.CANCELLED";
    pub const SESSION_INPUT_INJECTED: &str = "SESSION.INPUT_INJECTED";
    pub const SESSION_MODEL_SWAPPED: &str = "SESSION.MODEL_SWAPPED";
    // Assessment lifecycle.
    pub const ASSESSMENT_START: &str = "ASSESSMENT.START";
    pub const ASSESSMENT_FINISH: &str = "ASSESSMENT.FINISH";
    pub const TURN_END: &str = "TURN.END";
    pub const SCOPE_GRANT: &str = "SCOPE.GRANT";
    // LLM boundary.
    pub const LLM_REQUEST: &str = "LLM.REQUEST";
    pub const LLM_RESPONSE: &str = "LLM.RESPONSE";
    pub const LLM_RETRY: &str = "LLM.RETRY";
    pub const LLM_GAVE_UP: &str = "LLM.GAVE_UP";
    pub const LLM_MISCONFIGURED: &str = "LLM.MISCONFIGURED";
    pub const LLM_CLI_INVOKE: &str = "LLM.CLI_INVOKE";
    pub const LLM_CHAT: &str = "LLM.CHAT";
    pub const LLM_BAD_RESPONSE: &str = "LLM.BAD_RESPONSE";
    // Decisions.
    pub const DECISION_EXECUTE: &str = "DECISION.EXECUTE";
    pub const POLICY_REJECTED: &str = "POLICY.REJECTED";
    pub const APPROVAL_REQUESTED: &str = "APPROVAL.REQUESTED";
    pub const APPROVAL_DECIDED: &str = "APPROVAL.DECIDED";
    pub const BREAKER_BLOCKED: &str = "BREAKER.BLOCKED";
    pub const BREAKER_STUCK: &str = "BREAKER.STUCK";
    pub const PROVIDER_SELECTED: &str = "PROVIDER.SELECTED";
    pub const PROVIDER_REJECTED: &str = "PROVIDER.REJECTED";
    pub const DECISION_FINISH_PROPOSED: &str = "DECISION.FINISH_PROPOSED";
    pub const COMPLETION_VERDICT: &str = "COMPLETION.VERDICT";
    pub const DECISION_REPLY: &str = "DECISION.REPLY";
    pub const DECISION_NARRATE: &str = "DECISION.NARRATE";
    pub const HYPOTHESIS_CREATED: &str = "HYPOTHESIS.CREATED";
    pub const DECISION_WEB_SEARCH: &str = "DECISION.WEB_SEARCH";
    pub const DECISION_FILE_READ: &str = "DECISION.FILE_READ";
    pub const DECISION_FILE_WRITE: &str = "DECISION.FILE_WRITE";
    pub const FINDING_REPORTED: &str = "FINDING.REPORTED";
    pub const FINDING_UPDATED: &str = "FINDING.UPDATED";
    pub const VAULT_STORED: &str = "VAULT.STORED";
    pub const VAULT_RECALLED: &str = "VAULT.RECALLED";
    // Tool execution.
    pub const TOOL_CALL: &str = "TOOL.CALL";
    pub const TOOL_ARGV: &str = "TOOL.ARGV";
    pub const TOOL_GUARD_REJECTED: &str = "TOOL.GUARD_REJECTED";
    pub const TOOL_ATTEMPT: &str = "TOOL.ATTEMPT";
    pub const TOOL_RESULT: &str = "TOOL.RESULT";
    pub const TOOL_HTTP_CALL: &str = "TOOL.HTTP_CALL";
    pub const TOOL_HTTP_ERROR: &str = "TOOL.HTTP_ERROR";
    pub const TOOL_RESEARCH: &str = "TOOL.RESEARCH";
    pub const PARSER_RESULT: &str = "PARSER.RESULT";
    pub const TOOL_INEFFECTIVE: &str = "TOOL.INEFFECTIVE";
    pub const HARNESS_FEEDBACK: &str = "HARNESS.FEEDBACK";
    // State mutations.
    pub const STATE_ENTITY: &str = "STATE.ENTITY";
    pub const STATE_GRAPH_EDGE: &str = "STATE.GRAPH_EDGE";
    pub const STATE_EVIDENCE: &str = "STATE.EVIDENCE";
    pub const STATE_FAMILY: &str = "STATE.FAMILY";
    pub const STATE_REOPENED: &str = "STATE.REOPENED";
    pub const PLANNER_SUGGEST: &str = "PLANNER.SUGGEST";
    pub const STATE_SNAPSHOT: &str = "STATE.SNAPSHOT";
    pub const CONTEXT_BUILT: &str = "CONTEXT.BUILT";
    pub const CONTEXT_COMPACTED: &str = "CONTEXT.COMPACTED";

    /// Every tag, for the format test and UI filter lists.
    pub const ALL: &[&str] = &[
        SESSION_MESSAGE_RECEIVED,
        SESSION_WORKER_START,
        SESSION_REPLAYED,
        SESSION_TURN_START,
        SESSION_CANCELLED,
        SESSION_INPUT_INJECTED,
        SESSION_MODEL_SWAPPED,
        ASSESSMENT_START,
        ASSESSMENT_FINISH,
        TURN_END,
        SCOPE_GRANT,
        LLM_REQUEST,
        LLM_RESPONSE,
        LLM_RETRY,
        LLM_GAVE_UP,
        LLM_MISCONFIGURED,
        LLM_CLI_INVOKE,
        LLM_CHAT,
        LLM_BAD_RESPONSE,
        DECISION_EXECUTE,
        POLICY_REJECTED,
        APPROVAL_REQUESTED,
        APPROVAL_DECIDED,
        BREAKER_BLOCKED,
        BREAKER_STUCK,
        PROVIDER_SELECTED,
        PROVIDER_REJECTED,
        DECISION_FINISH_PROPOSED,
        COMPLETION_VERDICT,
        DECISION_REPLY,
        DECISION_NARRATE,
        HYPOTHESIS_CREATED,
        DECISION_WEB_SEARCH,
        DECISION_FILE_READ,
        DECISION_FILE_WRITE,
        FINDING_REPORTED,
        FINDING_UPDATED,
        VAULT_STORED,
        VAULT_RECALLED,
        TOOL_CALL,
        TOOL_ARGV,
        TOOL_GUARD_REJECTED,
        TOOL_ATTEMPT,
        TOOL_RESULT,
        TOOL_HTTP_CALL,
        TOOL_HTTP_ERROR,
        TOOL_RESEARCH,
        PARSER_RESULT,
        TOOL_INEFFECTIVE,
        HARNESS_FEEDBACK,
        STATE_ENTITY,
        STATE_GRAPH_EDGE,
        STATE_EVIDENCE,
        STATE_FAMILY,
        STATE_REOPENED,
        PLANNER_SUGGEST,
        STATE_SNAPSHOT,
        CONTEXT_BUILT,
        CONTEXT_COMPACTED,
    ];
}

/// One trace line. `msg` is a one-line human summary (grep-friendly);
/// `data` carries the structured, redacted payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceEntry {
    pub ts: i64,
    pub step: usize,
    #[serde(default)]
    pub assessment: String,
    pub tag: String,
    pub msg: String,
    #[serde(default)]
    pub data: serde_json::Value,
}

impl TraceEntry {
    pub fn new(
        step: usize,
        assessment: &str,
        tag: &str,
        msg: String,
        data: serde_json::Value,
    ) -> Self {
        Self {
            ts: now_ms(),
            step,
            assessment: assessment.to_string(),
            tag: tag.to_string(),
            msg,
            data: scrub_value(data),
        }
    }
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Redaction. Values are dropped, names/shapes are kept.
// ---------------------------------------------------------------------------

/// JSON key fragments whose VALUES must never land in a trace.
const SENSITIVE_FRAGMENTS: &[&str] = &[
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "auth",
    "credential", "cookie", "private_key", "client_secret", "sessionid",
];

fn key_is_sensitive(key: &str) -> bool {
    let k = key.to_lowercase();
    SENSITIVE_FRAGMENTS.iter().any(|f| k.contains(f))
}

/// Redact a JSON value recursively. Sensitive keys → "[redacted]";
/// strings → inline scrub; everything else passes through.
pub fn scrub_value(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let out: serde_json::Map<String, serde_json::Value> = map
                .into_iter()
                .map(|(k, val)| {
                    if key_is_sensitive(&k) {
                        (k, serde_json::Value::String("[redacted]".into()))
                    } else {
                        (k, scrub_value(val))
                    }
                })
                .collect();
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(scrub_value).collect())
        }
        serde_json::Value::String(s) => serde_json::Value::String(scrub_text(&s, TRACE_STR_CAP)),
        other => other,
    }
}

fn is_b64url(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '='
}

fn looks_like_jwt(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| p.len() >= 8 && p.chars().all(is_b64url))
}

/// Scrub free text: `Bearer <value>` → `Bearer [redacted]`, standalone
/// JWT-shaped tokens → `[jwt]`, exact registered secrets → `[redacted]`,
/// then truncate to `cap` chars.
pub fn scrub_text(s: &str, cap: usize) -> String {
    let mut out = String::with_capacity(s.len().min(cap));
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() && out.chars().count() < cap {
        // Case-insensitive "bearer " match.
        if i + 7 <= chars.len()
            && chars[i..i + 7].iter().collect::<String>().eq_ignore_ascii_case("bearer ")
        {
            out.push_str(&chars[i..i + 7].iter().collect::<String>());
            i += 7;
            // Consume the credential up to whitespace, ';', quote or ','.
            while i < chars.len()
                && !chars[i].is_whitespace()
                && chars[i] != ';'
                && chars[i] != '"'
                && chars[i] != '\''
                && chars[i] != ','
            {
                i += 1;
            }
            out.push_str("[redacted]");
            continue;
        }
        // Standalone JWT-shaped token (bounded scan from token chars/dots).
        if is_b64url(chars[i]) || chars[i] == '.' {
            let mut j = i;
            while j < chars.len() && (is_b64url(chars[j]) || chars[j] == '.') {
                j += 1;
            }
            let token: String = chars[i..j].iter().collect();
            if token.len() >= 30 && looks_like_jwt(&token) {
                out.push_str("[jwt]");
                i = j;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    if i < chars.len() {
        out.push_str(&format!("…[truncated, {} chars total]", s.chars().count()));
    }
    replace_registered_secrets(&out)
}

// ---------------------------------------------------------------------------
// Exact-secret registry (out-of-band vault values).
// ---------------------------------------------------------------------------

/// Minimum secret length worth exact-matching: shorter strings collide
/// with ordinary text (over-redaction). Short values stay covered by the
/// key/Bearer/JWT patterns above — and, more importantly, never enter a
/// prompt in the first place.
const MIN_SECRET_LEN: usize = 8;
/// Cap so a pathological session can't grow the per-thread set forever.
const MAX_REGISTERED_SECRETS: usize = 128;

thread_local! {
    static REGISTERED_SECRETS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// Register an exact secret value for scrubbing on this thread. Called
/// by the vault-reference substitution path for every resolved value, so
/// a value injected into tool argv can never land in a trace file even
/// though no key/Bearer/JWT pattern matches it. Thread-local: the drive
/// loop runs single-threaded per session, and traces are written on the
/// same thread that substitutes.
pub fn register_secret_for_scrubbing(value: &str) {
    let v = value.trim().to_string();
    if v.chars().count() < MIN_SECRET_LEN {
        return;
    }
    REGISTERED_SECRETS.with(|set| {
        let mut set = set.borrow_mut();
        if !set.contains(&v) {
            set.push(v);
            let overflow = set.len().saturating_sub(MAX_REGISTERED_SECRETS);
            if overflow > 0 {
                set.drain(0..overflow);
            }
        }
    });
}

/// Drop all registered secrets on this thread (turn hygiene in tests).
pub fn clear_registered_secrets() {
    REGISTERED_SECRETS.with(|set| set.borrow_mut().clear());
}

fn replace_registered_secrets(s: &str) -> String {
    let secrets: Vec<String> = REGISTERED_SECRETS
        .with(|set| set.borrow().clone());
    if secrets.is_empty() {
        return s.to_string();
    }
    let mut out = s.to_string();
    for secret in &secrets {
        if out.contains(secret) {
            out = out.replace(secret, "[redacted]");
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Writer.
// ---------------------------------------------------------------------------

pub fn traces_dir() -> PathBuf {
    state_dir().join("sessions")
}

fn trace_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.trace.jsonl"))
}

/// Append-only JSONL trace writer. Mirrors `SessionWriter` semantics.
pub struct TraceWriter {
    file: File,
}

impl TraceWriter {
    /// Open (or create) the per-session trace file, shrinking the tail if
    /// it grew past [`TRACE_MAX_BYTES`].
    pub fn open(session_id: &str) -> Result<Self, String> {
        Self::open_in(&traces_dir(), session_id)
    }

    pub fn open_in(dir: &Path, session_id: &str) -> Result<Self, String> {
        if !crate::infra::sessions::is_valid_id(session_id) {
            return Err(format!("invalid session id: {session_id}"));
        }
        fs::create_dir_all(dir).map_err(|e| format!("create trace dir: {e}"))?;
        enforce_cap(&trace_path(dir, session_id))?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(trace_path(dir, session_id))
            .map_err(|e| format!("open trace file: {e}"))?;
        Ok(Self { file })
    }

    /// Open an ad-hoc trace file by explicit path (CLI/TUI runs).
    pub fn open_path(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("create trace dir: {e}"))?;
        }
        enforce_cap(path)?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| format!("open trace file: {e}"))?;
        Ok(Self { file })
    }

    pub fn append(&mut self, entry: &TraceEntry) {
        // Best-effort by contract: tracing must never fail the loop.
        if let Ok(line) = serde_json::to_string(entry) {
            let _ = writeln!(self.file, "{line}");
            let _ = self.file.flush();
        }
    }

    /// Read the tail: total raw lines, parsed entries (malformed skipped),
    /// whether output was cut to `max_lines`.
    pub fn read_tail(
        dir: &Path,
        session_id: &str,
        max_lines: usize,
    ) -> Result<(Vec<TraceEntry>, usize, bool), String> {
        if !crate::infra::sessions::is_valid_id(session_id) {
            return Err(format!("invalid session id: {session_id}"));
        }
        Self::read_tail_path(&trace_path(dir, session_id), max_lines)
    }

    pub fn read_tail_path(
        path: &Path,
        max_lines: usize,
    ) -> Result<(Vec<TraceEntry>, usize, bool), String> {
        let file = File::open(path).map_err(|e| format!("open trace: {e}"))?;
        let lines: Vec<String> = BufReader::new(file)
            .lines()
            .filter_map(|l| l.ok())
            .filter(|l| !l.trim().is_empty())
            .collect();
        let total = lines.len();
        let start = total.saturating_sub(max_lines);
        let entries: Vec<TraceEntry> = lines[start..]
            .iter()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        Ok((entries, total, total > max_lines))
    }

    /// Delete trace files older than `days`. Runs once at startup.
    pub fn prune_older_than(dir: &Path, days: u64) {
        let cutoff_ms = now_ms() - (days as i64) * 86_400_000;
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                continue;
            }
            if !path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.ends_with(".trace.jsonl"))
                .unwrap_or(false)
            {
                continue;
            }
            let old = entry
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0);
            if old < cutoff_ms {
                let _ = fs::remove_file(&path);
            }
        }
    }
}

/// If the trace file exceeds the cap, rewrite it keeping the byte tail.
fn enforce_cap(path: &Path) -> Result<(), String> {
    let Ok(meta) = fs::metadata(path) else {
        return Ok(()); // no file yet
    };
    if meta.len() <= TRACE_MAX_BYTES {
        return Ok(());
    }
    let text = fs::read_to_string(path).map_err(|e| format!("read trace: {e}"))?;
    let mut kept: Vec<&str> = Vec::new();
    let mut bytes: u64 = 0;
    for line in text.lines().rev() {
        let cost = line.len() as u64 + 1;
        if bytes + cost > TRACE_KEEP_BYTES && !kept.is_empty() {
            break;
        }
        bytes += cost;
        kept.push(line);
    }
    kept.reverse();
    fs::write(path, kept.join("\n") + "\n").map_err(|e| format!("shrink trace: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_tags_are_capital_letters() {
        assert!(!tag::ALL.is_empty());
        for t in tag::ALL {
            assert!(
                t.chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '.' || c == '_'),
                "tag not CAPITAL: {t}"
            );
            assert!(t.contains('.'), "tag needs AREA.EVENT shape: {t}");
        }
    }

    #[test]
    fn bearer_values_redacted_names_kept() {
        let s = scrub_text(
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dummy-signature-value-here; Content-Type: application/json",
            500,
        );
        assert!(s.contains("Authorization: Bearer [redacted]"), "got: {s}");
        assert!(s.contains("Content-Type: application/json"), "got: {s}");
    }

    #[test]
    fn standalone_jwt_redacted() {
        let jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJkYXRhIjoxLCJiaWQiOjF9.c2lnbmF0dXJlLXZvby1iYXI";
        let s = scrub_text(&format!("token {jwt} ok"), 500);
        assert!(!s.contains(&jwt[..20]), "jwt leaked: {s}");
        assert!(s.contains("[jwt]"), "got: {s}");
    }

    #[test]
    fn sensitive_json_keys_redacted_shapes_kept() {
        let v = serde_json::json!({
            "email": "a@b.c",
            "password": "hunter2",
            "method": "POST",
            "nested": {"api_key": "K", "count": 3}
        });
        let out = scrub_value(v);
        assert_eq!(out["email"], serde_json::json!("a@b.c"));
        assert_eq!(out["password"], serde_json::json!("[redacted]"));
        assert_eq!(out["nested"]["api_key"], serde_json::json!("[redacted]"));
        assert_eq!(out["nested"]["count"], serde_json::json!(3));
    }

    #[test]
    fn entry_constructor_scrubs_data() {
        let e = TraceEntry::new(
            1,
            "a",
            tag::TOOL_HTTP_CALL,
            "x".into(),
            serde_json::json!({"headers": "Authorization: Bearer abcdefgh.abcdefgh.abcdefgh"}),
        );
        let s = serde_json::to_string(&e).unwrap();
        assert!(!s.contains("abcdefgh.abcdefgh"), "leaked: {s}");
    }

    #[test]
    fn registered_secrets_scrubbed_bare_values_kept() {
        clear_registered_secrets();
        // A bare value with no key/Bearer/JWT shape (e.g. an argv token
        // after vault substitution) is only caught via registration.
        register_secret_for_scrubbing("s3cr3t-vault-value");
        let s = scrub_text("nmap --password s3cr3t-vault-value --intensity normal", 500);
        assert!(!s.contains("s3cr3t-vault-value"), "leaked: {s}");
        assert!(s.contains("[redacted]"), "got: {s}");
        assert!(s.contains("--intensity normal"), "over-redacted: {s}");
        // JSON paths go through the same scrubber.
        let v = scrub_value(serde_json::json!({"argv": ["tool", "s3cr3t-vault-value"]}));
        assert_eq!(v["argv"][1], serde_json::json!("[redacted]"));
        // Short strings are not registered (over-redaction guard).
        register_secret_for_scrubbing("abc");
        let s = scrub_text("abc def", 500);
        assert_eq!(s, "abc def");
        clear_registered_secrets();
        let s = scrub_text("s3cr3t-vault-value here", 500);
        assert!(s.contains("s3cr3t-vault-value"), "clear must restore: {s}");
    }

    #[test]
    fn writer_appends_and_reads_tail() {
        let dir = std::env::temp_dir().join(format!("medusa-trace-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut w = TraceWriter::open_in(&dir, "ses-1").unwrap();
        for i in 0..5 {
            w.append(&TraceEntry::new(i, "a", tag::TOOL_RESULT, format!("m{i}"), serde_json::json!({})));
        }
        // Malformed tail line is skipped, never fatal.
        OpenOptions::new()
            .append(true)
            .open(dir.join("ses-1.trace.jsonl"))
            .unwrap()
            .write_all(b"{bad json\n")
            .unwrap();
        drop(w);
        let mut w = TraceWriter::open_in(&dir, "ses-1").unwrap();
        w.append(&TraceEntry::new(5, "a", tag::TOOL_RESULT, "m5".into(), serde_json::json!({})));
        let (entries, total, truncated) = TraceWriter::read_tail(&dir, "ses-1", 3).unwrap();
        assert_eq!(total, 7);
        assert!(truncated);
        // Last 3 raw lines are m4, malformed (skipped), m5.
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].msg, "m4");
        assert_eq!(entries[1].msg, "m5");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_traversal_ids() {
        let dir = std::env::temp_dir();
        assert!(TraceWriter::open_in(&dir, "../evil").is_err());
        assert!(TraceWriter::read_tail(&dir, "../evil", 10).is_err());
    }
}
