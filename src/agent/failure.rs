//! Structured failure taxonomy + recovery feedback for the LLM.
//!
//! Every failure Cipher surfaces to the model carries: the failed
//! capability, a machine-stable category, sanitized observed facts, a
//! clearly-labeled unconfirmed suspicion, and one concrete next
//! diagnostic step. Facts and guesses are never blended: the model
//! must be able to tell what happened from what Cipher thinks it means.
//!
//! Generic by construction: categories describe *how* something failed
//! (validation, transport, auth, ...), never *which application* or
//! endpoint was involved.

use super::executor::ToolResult;
use super::provider::ProviderError;
use super::policy::PolicyError;

/// How a capability request failed. Covers the full pipeline from
/// argument validation to response parsing so recovery advice can be
/// specific instead of "it failed, try something else".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureCategory {
    /// Arguments rejected against the capability schema (unknown option,
    /// wrong type, malformed headers, body without Content-Type).
    Argument,
    /// Target outside the granted assessment scope.
    Scope,
    /// Destructive capability without approval.
    Risk,
    /// No healthy provider, or an option no provider supports.
    Provider,
    /// Network-level failure: DNS, refused, reset, TLS, malformed URL.
    Transport,
    /// The target did not answer in time.
    Timeout,
    /// The server answered 401/403: credentials missing, malformed, or
    /// rejected. Distinct from transport — the request DID arrive.
    Auth,
    /// The server answered any other non-2xx status.
    HttpStatus(u16),
    /// Tool output could not be parsed into observations.
    Parse,
    /// The tool itself exited non-zero / reported an error.
    Tool,
}

impl FailureCategory {
    /// Stable machine-readable name (also used in traces).
    pub fn name(&self) -> &'static str {
        match self {
            Self::Argument => "ARGUMENT",
            Self::Scope => "SCOPE",
            Self::Risk => "RISK",
            Self::Provider => "PROVIDER",
            Self::Transport => "TRANSPORT",
            Self::Timeout => "TIMEOUT",
            Self::Auth => "AUTH",
            Self::HttpStatus(_) => "HTTP_STATUS",
            Self::Parse => "PARSE",
            Self::Tool => "TOOL",
        }
    }

    pub fn from_policy_error(err: &PolicyError) -> Self {
        match err {
            PolicyError::InvalidArguments { .. } => Self::Argument,
            PolicyError::OutOfScope { .. } => Self::Scope,
            PolicyError::HighRiskRequiresApproval { .. } => Self::Risk,
            PolicyError::UnknownCapability(_) => Self::Argument,
        }
    }

    pub fn from_provider_error(err: &ProviderError) -> Self {
        match err {
            ProviderError::NoProviderRegistered { .. }
            | ProviderError::NoProviderAvailable { .. }
            | ProviderError::OptionUnsupported { .. } => Self::Provider,
        }
    }

    /// Classify a finished tool result. Success is never classified here
    /// (callers only classify failures), except HTTP 401/403 responses:
    /// providers report those as exit-0 observations, but for recovery
    /// purposes an auth rejection is a failure of the *request*, and the
    /// model must hear that explicitly.
    pub fn from_tool_result(result: &ToolResult) -> Self {
        if result.timed_out {
            return Self::Timeout;
        }
        if let Some(err) = &result.error {
            if result.is_non_retryable() {
                return Self::Argument;
            }
            let _ = err;
            return Self::Transport;
        }
        if let Some(code) = http_status_of(result) {
            return match code {
                401 | 403 => Self::Auth,
                other => Self::HttpStatus(other),
            };
        }
        Self::Tool
    }

    /// Structured recovery feedback for `last_error`. `facts` must already
    /// be sanitized (names, lengths, exit codes — never tokens or bodies).
    pub fn recovery(&self, capability: &str, target: &str, facts: &str) -> String {
        // Defense in depth: facts arrive pre-sanitized, but tool errors can
        // echo credentials (e.g. a rejected Authorization header). Scrub
        // again so tokens never reach model context through this path.
        let facts = crate::infra::trace::scrub_text(facts, 2000);
        let (suspicion, next) = match self {
            Self::Argument => (
                "one of the named options does not match the capability schema (unconfirmed which rule tripped until the details are read)",
                "fix ONLY the named option per the schema/hint and retry the identical target; do not change anything else",
            ),
            Self::Scope => (
                "the target is outside the granted assessment scope",
                "use an in-scope target, or ask the user to authorize the new target — discovered assets are not automatically in scope",
            ),
            Self::Risk => (
                "the capability is classified destructive and needs explicit approval",
                "request approval, or pick a non-destructive capability that answers the same question",
            ),
            Self::Provider => (
                "no healthy provider can run this capability/option combination here",
                "retry without the unsupported option, or use a different capability for the same question",
            ),
            Self::Transport => (
                "network-level failure (DNS, refused, reset, TLS) — the request likely never arrived (unconfirmed)",
                "verify the target is reachable, then retry unchanged; transient failures resolve on their own",
            ),
            Self::Timeout => (
                "the target did not answer in time — too slow or too broad a request (unconfirmed)",
                "narrow the target and retry; do not widen it",
            ),
            Self::Auth => (
                "credentials missing, malformed, or rejected — OR the token expired (unconfirmed which)",
                "verify the Authorization header is exactly `Authorization: Bearer <token>` plus Content-Type, sent as an object of two headers; re-authenticate for a fresh token if it may have expired; do NOT resend the identical request",
            ),
            Self::HttpStatus(code) if *code >= 500 => (
                "server-side failure — the request arrived but the server errored (unconfirmed cause)",
                "retry once after a pause; if it persists, record what was learned and move to a different question",
            ),
            Self::HttpStatus(_) => (
                "the endpoint, method, or payload was rejected by the server (unconfirmed which part)",
                "read the response body for the server's stated reason, then fix exactly one of path/method/body and retry",
            ),
            Self::Parse => (
                "raw output is preserved as evidence but no parser understood it",
                "inspect the raw evidence, then try a different capability for the same question",
            ),
            Self::Tool => (
                "the tool itself reported an error (unconfirmed whether inputs or target state caused it)",
                "read stderr/exit code, fix the inputs, and retry once",
            ),
        };
        format!(
            "`{capability}` on `{target}` failed [{cat}].\nObserved facts: {facts}\nSuspected cause (unconfirmed): {suspicion}.\nNext diagnostic step: {next}.",
            cat = self.name(),
        )
    }
}

/// Best-effort HTTP status extraction from medusa-http evidence JSON
/// (`{"status": 401, ...}`). Returns None when the output is not shaped
/// like an HTTP evidence object.
fn http_status_of(result: &ToolResult) -> Option<u16> {
    let output = result.combined_output();
    let start = output.find("\"status\"")?;
    let after = output[start..].find(':')?;
    let digits: String = output[start + after + 1..]
        .chars()
        .skip_while(|c| c.is_whitespace())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::model::{OptionSet, OptionValue};

    fn http_result(status: u16) -> ToolResult {
        ToolResult {
            tool_id: "medusa-http".into(),
            capability: "http.request".into(),
            target: "http://127.0.0.1:9/x".into(),
            exit_code: 0,
            stdout: format!(r#"{{"url":"http://127.0.0.1:9/x","method":"GET","status":{status},"content_type":"text/html","body_length":10,"body_snippet":"hi"}}"#),
            stderr: String::new(),
            timed_out: false,
            error: None,
        }
    }

    #[test]
    fn names_are_capital() {
        for cat in [
            FailureCategory::Argument,
            FailureCategory::Scope,
            FailureCategory::Risk,
            FailureCategory::Provider,
            FailureCategory::Transport,
            FailureCategory::Timeout,
            FailureCategory::Auth,
            FailureCategory::HttpStatus(500),
            FailureCategory::Parse,
            FailureCategory::Tool,
        ] {
            assert!(cat
                .name()
                .chars()
                .all(|c| c.is_ascii_uppercase() || c == '_'));
        }
    }

    #[test]
    fn policy_errors_map_to_categories() {
        assert_eq!(
            FailureCategory::from_policy_error(&PolicyError::OutOfScope {
                target: "x".into(),
                scope: "y".into()
            }),
            FailureCategory::Scope
        );
        assert_eq!(
            FailureCategory::from_policy_error(&PolicyError::HighRiskRequiresApproval {
                capability: "c".into()
            }),
            FailureCategory::Risk
        );
        assert_eq!(
            FailureCategory::from_policy_error(&PolicyError::InvalidArguments {
                capability: "c".into(),
                details: "d".into()
            }),
            FailureCategory::Argument
        );
    }

    #[test]
    fn timeout_beats_error_text() {
        let mut r = http_result(200);
        r.timed_out = true;
        r.error = Some("anything".into());
        assert_eq!(FailureCategory::from_tool_result(&r), FailureCategory::Timeout);
    }

    #[test]
    fn deterministic_errors_are_argument_failures() {
        let r = ToolResult::error_non_retryable("medusa-http", "http.request", "t", "invalid arguments: x".into());
        assert_eq!(FailureCategory::from_tool_result(&r), FailureCategory::Argument);
    }

    #[test]
    fn plain_errors_are_transport_failures() {
        let r = ToolResult::error("nmap", "network.port_scan", "t", "connection refused".into());
        assert_eq!(FailureCategory::from_tool_result(&r), FailureCategory::Transport);
    }

    #[test]
    fn http_401_and_403_are_auth_failures() {
        // A synthetic 401: exit-0 observation, but an auth failure of the
        // request itself — the recovery loop must hear that explicitly.
        assert_eq!(
            FailureCategory::from_tool_result(&http_result(401)),
            FailureCategory::Auth
        );
        assert_eq!(
            FailureCategory::from_tool_result(&http_result(403)),
            FailureCategory::Auth
        );
        assert_eq!(
            FailureCategory::from_tool_result(&http_result(404)),
            FailureCategory::HttpStatus(404)
        );
        assert_eq!(
            FailureCategory::from_tool_result(&http_result(500)),
            FailureCategory::HttpStatus(500)
        );
    }

    #[test]
    fn nonzero_exit_is_a_tool_failure() {
        let r = ToolResult {
            tool_id: "nmap".into(),
            capability: "network.port_scan".into(),
            target: "t".into(),
            exit_code: 1,
            stdout: String::new(),
            stderr: "boom".into(),
            timed_out: false,
            error: None,
        };
        assert_eq!(FailureCategory::from_tool_result(&r), FailureCategory::Tool);
    }

    #[test]
    fn recovery_splits_facts_from_suspicion() {
        let fb = FailureCategory::Auth.recovery("http.request", "http://x/", "status=401");
        assert!(fb.contains("http.request"), "{fb}");
        assert!(fb.contains("[AUTH]"), "{fb}");
        assert!(fb.contains("Observed facts: status=401"), "{fb}");
        assert!(fb.contains("unconfirmed"), "{fb}");
        assert!(fb.contains("Next diagnostic step:"), "{fb}");
        // No secret material in the template itself.
        assert!(!fb.contains("Bearer eyJ"), "{fb}");
        let _ = OptionSet::new();
        let _ = OptionValue::Bool(true);
    }

    #[test]
    fn recovery_scrubs_tokens_from_facts() {        // Tool errors echo rejected headers including the token: the
        // feedback path must not become a credential leak.
        let facts = "medusa-http failed: Bad Header: invalid header 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXZvby1iYXI'";
        let fb = FailureCategory::Transport.recovery("http.request", "http://x/", facts);
        assert!(!fb.contains("eyJhbGciOiJIUzI1NiJ9"), "token leaked: {fb}");
        assert!(fb.contains("Authorization"), "header name must survive: {fb}");
        assert!(fb.contains("[TRANSPORT]"), "{fb}");
    }

    #[test]
    fn every_category_renders_structured_feedback() {
        // Every category must produce the facts/suspicion/next-step shape
        // so no failure path can ever degrade to a bare "it failed".
        for cat in [
            FailureCategory::Argument,
            FailureCategory::Scope,
            FailureCategory::Risk,
            FailureCategory::Provider,
            FailureCategory::Timeout,
            FailureCategory::HttpStatus(404),
            FailureCategory::HttpStatus(500),
            FailureCategory::Parse,
            FailureCategory::Tool,
        ] {
            let fb = cat.recovery("some.cap", "some-target", "fact=1");
            assert!(fb.contains("some.cap"), "{fb}");
            assert!(fb.contains(&format!("[{}]", cat.name())), "{fb}");
            assert!(fb.contains("Observed facts: fact=1"), "{fb}");
            assert!(fb.contains("Suspected cause (unconfirmed):"), "{fb}");
            assert!(fb.contains("Next diagnostic step:"), "{fb}");
        }
    }
}
