//! Internal HTTP request provider (`medusa-http`): the built-in
//! implementation behind the `http.request`, `api.auth_testing` and
//! `api.bola_testing` capabilities. There is no external executable —
//! the provider performs the request itself via ureq (already the
//! model-transport HTTP client) and synthesizes JSON evidence that the
//! parsers turn into observations.
//!
//! This closes the action-space gap for business-logic verification:
//! the model could always *decide* to test a login bypass or an IDOR
//! primitive, but previously had no capability that could issue a
//! crafted raw request — only whole-tool invocations with fixed argv.

use std::time::Duration;

use super::executor::ToolResult;
use super::model::OptionValue;
use super::provider::{CapabilityProvider, CapabilityRequest, ExecutionContext};
use super::research::window_text;

pub const HTTP_CAPABILITIES: [&str; 3] = ["http.request", "api.auth_testing", "api.bola_testing"];

/// Width of the response-body window returned to the model per request
/// (chars). http.request is a payload-verification tool: the model reads
/// the body to confirm/reject a finding (SSTI, SQLi, IDOR) or to scan a
/// large JSON listing. The FULL body is captured; `grep`/`offset` choose
/// WHICH window of it rides the evidence, so content past this width is
/// reachable (page with `offset`, jump with `grep`) instead of being
/// hard-truncated with no recovery path.
const BODY_WINDOW_CHARS: usize = 12_000;
/// Hard cap on the raw body we read into memory before windowing, so a
/// pathological multi-MB response can't blow up the process. Large enough
/// that realistic API/HTML payloads (the ~47KB challenge list) are fully
/// pageable.
const BODY_READ_CAP_BYTES: u64 = 2 * 1024 * 1024;

/// Read a response body into a string, bounded by [`BODY_READ_CAP_BYTES`]
/// so a pathological multi-MB response can't exhaust memory. Lossy UTF-8 so
/// binary-ish bodies still yield readable evidence.
fn read_body_capped(resp: ureq::Response) -> String {
    use std::io::Read;
    let mut buf = Vec::with_capacity(64 * 1024);
    let mut reader = resp.into_reader().take(BODY_READ_CAP_BYTES);
    let _ = reader.read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

/// Build the evidence JSON for one response, windowing the full body with
/// `grep`/`offset` (same paging contract as `web.research`). `body_length`
/// reports the TRUE total length; `body_snippet` carries the selected window
/// and `note` tells the model how to reach the rest. This replaces the old
/// hard 8KB truncation that hid everything past the head with no recovery.
fn body_evidence(
    url: &str,
    method: &str,
    status: u16,
    content_type: &str,
    full_body: &str,
    grep: Option<&str>,
    offset: usize,
) -> serde_json::Value {
    let win = window_text(full_body, grep, offset, BODY_WINDOW_CHARS);
    let returned = win.text.chars().count();
    let mut evidence = serde_json::json!({
        "url": url,
        "method": method,
        "status": status,
        "content_type": content_type,
        "body_length": win.total_chars,
        "returned_chars": returned,
        "offset": win.offset,
        "body_snippet": win.text,
    });
    if let Some(matched) = win.grep_matched {
        evidence["grep"] = serde_json::json!(grep.unwrap_or("").trim());
        evidence["grep_matched"] = serde_json::json!(matched);
        if !matched {
            evidence["note"] = serde_json::json!(
                "grep pattern not found in the body — try a different/shorter pattern, or omit grep and use offset to page through"
            );
        }
    } else if win.offset + returned < win.total_chars {
        // More body remains past this window: tell the model how to get it.
        evidence["note"] = serde_json::json!(format!(
            "{} of {} chars shown from offset {}; more remains — pass grep=<text> to jump to a section, or offset={} to continue",
            returned,
            win.total_chars,
            win.offset,
            win.offset + returned
        ));
    }
    evidence
}

pub struct HttpRequestProvider {
    timeout: Duration,
}

impl Default for HttpRequestProvider {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
        }
    }
}

impl HttpRequestProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// "host:port/path" → "http://host:port/path"; already-schemed targets
    /// pass through. Also repairs mangled backslashes (the model has been
    /// seen emitting `http:\127.0.0.1:3000`), so a borderline target still
    /// reaches the server instead of failing an encoding check.
    fn normalize_url(target: &str) -> String {
        let mut t = target.trim().to_string();
        if t.is_empty() {
            return t;
        }
        // Collapse mangled schemes: `http:\host` and `http:\\host`.
        // Handle the double-backslash before the single so `\\` doesn't
        // turn into `/\`.
        t = t
            .replace("http:\\\\", "http://")
            .replace("https:\\\\", "https://")
            .replace("http:\\", "http://")
            .replace("https:\\", "https://");
        if t.starts_with("http://") || t.starts_with("https://") {
            t
        } else {
            format!("http://{t}")
        }
    }
}

/// Resolve a `path` option against a URL's origin, overriding any path the
/// target already carried. `http.request`'s target is the full URL, so a
/// separate `path` is redundant — but the model routinely borrows `path`
/// from the sibling `http.probe` capability, so accepting it (instead of
/// rejecting the call) is the forgiving, consistent behavior. `/rest/x` and
/// `rest/x` both resolve; a path with its own query string is kept intact.
fn apply_path(url: &str, path: &str) -> String {
    let path = path.trim();
    if path.is_empty() {
        return url.to_string();
    }
    let Some((scheme, rest)) = url.split_once("://") else {
        // Unschemed shouldn't happen (normalize_url runs first); leave as-is.
        return url.to_string();
    };
    // Authority = everything up to the first path/query/fragment delimiter.
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..auth_end];
    let sep = if path.starts_with('/') { "" } else { "/" };
    format!("{scheme}://{authority}{sep}{path}")
}

/// Strip embedded credentials from a URL for logging (`user:pass@host`
/// → `[redacted]@host`). Structure kept, secrets dropped.
pub(crate) fn redact_url(url: &str) -> String {
    match url.split_once("://") {
        Some((scheme, rest)) => match rest.rsplit_once('@') {
            Some((_, host)) => format!("{scheme}://[redacted]@{host}"),
            None => url.to_string(),
        },
        None => url.to_string(),
    }
}

/// Resolved HTTP call (no I/O): everything `execute` needs.
#[derive(Debug)]
struct PreparedCall {
    url: String,
    method: String,
    headers: Vec<(String, String)>,
    body: Option<String>,
    follow: bool,
}

/// Build the call from semantic options. `headers` must already be a
/// structured map (policy validates + migrates before execution); a
/// strictly well-formed legacy string is still accepted here as defense
/// in depth for direct callers, anything ambiguous is an error — never
/// silently merged into one header.
fn prepare_call(request: &CapabilityRequest) -> Result<PreparedCall, String> {
    let mut url = HttpRequestProvider::normalize_url(&request.target);
    let mut method = "GET".to_string();
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut headers_seen = false;
    let mut body: Option<String> = None;
    let mut follow = true;
    for (name, value) in &request.options {
        match (name.as_str(), value) {
            ("method", OptionValue::Str(m)) => method = m.to_uppercase(),
            ("headers", OptionValue::Map(m)) => {
                headers_seen = true;
                headers =
                    super::http_headers::validate_header_map(m).map_err(|e| {
                        format!("invalid headers option: {e}")
                    })?;
            }
            ("headers", OptionValue::Str(h)) => {
                headers_seen = true;
                headers = super::http_headers::parse_legacy_headers(h).map_err(|e| {
                    format!("invalid headers option: {e}")
                })?;
            }
            ("body", OptionValue::Str(b)) => body = Some(b.clone()),
            ("follow_redirects", OptionValue::Bool(b)) => follow = *b,
            // Lenient convenience: the model often supplies `path` (valid on
            // http.probe) instead of putting it in the URL. Fold it onto the
            // target's origin rather than rejecting the whole request.
            ("path", OptionValue::Str(p)) => url = apply_path(&url, p),
            _ => {}
        }
    }
    // A body without an explicit method means POST.
    if body.is_some() && !request.options.contains_key("method") {
        method = "POST".to_string();
    }
    if body.as_ref().is_some_and(|b| !b.trim().is_empty()) && !headers_seen {
        return Err(
            "body is present but no headers were given: add {\"Content-Type\": \"...\"} to `headers`".to_string(),
        );
    }
    if body.as_ref().is_some_and(|b| !b.trim().is_empty())
        && !super::http_headers::has_content_type(&headers)
    {
        return Err(
            "body is present but no Content-Type header was given: add {\"Content-Type\": \"...\"} to `headers`".to_string(),
        );
    }
    Ok(PreparedCall {
        url,
        method,
        headers,
        body,
        follow,
    })
}

impl CapabilityProvider for HttpRequestProvider {
    fn id(&self) -> &str {
        "medusa-http"
    }

    fn capabilities(&self) -> &[String] {
        // Static slice stored as String allocations once per call site is
        // wasteful; a thread-local keeps the trait signature (borrowed
        // slice) without per-call allocation.
        static CAPS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
        CAPS.get_or_init(|| HTTP_CAPABILITIES.iter().map(|s| s.to_string()).collect())
    }

    fn priority(&self) -> u8 {
        40 // real scanners win for their own jobs; this is the fallback
    }

    fn supports_option(&self, _capability: &str, option: &str) -> bool {
        matches!(
            option,
            "method" | "headers" | "body" | "follow_redirects" | "grep" | "offset" | "path"
        )
    }

    fn is_available(&self, _env: &crate::model::EnvironmentState) -> bool {
        true // built into medusa
    }

    fn execute(&self, request: &CapabilityRequest, _ctx: &ExecutionContext) -> ToolResult {
        let prepared = match prepare_call(request) {
            Ok(p) => p,
            Err(e) => {
                return ToolResult::error_non_retryable(
                    "medusa-http",
                    &request.capability,
                    &request.target,
                    format!("invalid arguments: {e}"),
                );
            }
        };
        let url = prepared.url;
        let method = prepared.method;
        let headers = prepared.headers;
        let body = prepared.body;
        let follow = prepared.follow;

        // Paging options: window a large body instead of hard-truncating.
        // `grep` jumps to the first match; `offset` continues from a char
        // index. Same contract as `web.research`.
        let grep = match request.options.get("grep") {
            Some(OptionValue::Str(s)) => Some(s.clone()),
            _ => None,
        };
        let offset = match request.options.get("offset") {
            Some(OptionValue::Num(n)) if *n >= 0.0 => *n as usize,
            _ => 0,
        };

        // ureq 2.x: redirect policy lives on the Agent, so pick the agent
        // matching the requested redirect behavior.
        let agent = if follow {
            ureq::AgentBuilder::new().timeout(self.timeout).build()
        } else {
            ureq::AgentBuilder::new()
                .timeout(self.timeout)
                .redirects(0)
                .build()
        };
        let mut req = agent.request(&method, &url);
        for (name, value) in &headers {
            req = req.set(name, value);
        }
        let response = match body {
            Some(b) => req.send_string(&b),
            None => req.call(),
        };

        match response {
            Ok(resp) => {
                let status = resp.status();
                let content_type = resp.content_type().to_string();
                let body_text = read_body_capped(resp);
                let evidence = body_evidence(
                    &url,
                    &method,
                    status,
                    &content_type,
                    &body_text,
                    grep.as_deref(),
                    offset,
                );
                ToolResult {
                    tool_id: "medusa-http".into(),
                    capability: request.capability.clone(),
                    target: request.target.clone(),
                    exit_code: 0,
                    stdout: serde_json::to_string(&evidence).unwrap_or_default(),
                    stderr: String::new(),
                    timed_out: false,
                    error: None,
                }
            }
            Err(ureq::Error::Status(code, resp)) => {
                // Non-2xx/3xx is a valid security observation, not a failure.
                let content_type = resp.content_type().to_string();
                let body_text = read_body_capped(resp);
                let evidence = body_evidence(
                    &url,
                    &method,
                    code,
                    &content_type,
                    &body_text,
                    grep.as_deref(),
                    offset,
                );
                ToolResult {
                    tool_id: "medusa-http".into(),
                    capability: request.capability.clone(),
                    target: request.target.clone(),
                    exit_code: 0,
                    stdout: serde_json::to_string(&evidence).unwrap_or_default(),
                    stderr: String::new(),
                    timed_out: false,
                    error: None,
                }
            }
            Err(e) => {
                // Deterministic input errors (bad URL, bad header) must
                // not burn the automatic retries — identical input fails
                // identically. Mark them non-retryable so the loop
                // reports the failure to the model immediately.
                let deterministic = matches!(
                    &e,
                    ureq::Error::Transport(t)
                        if matches!(
                            t.kind(),
                            ureq::ErrorKind::InvalidUrl
                                | ureq::ErrorKind::UnknownScheme
                                | ureq::ErrorKind::BadHeader
                        )
                );
                let msg = format!("request to {url} failed: {e}");
                // When the failure is our own header serialization, tell
                // the model the exact contract instead of echoing only the
                // rejected blob — otherwise it retries the same shape.
                let msg = if matches!(
                    &e,
                    ureq::Error::Transport(t)
                        if matches!(t.kind(), ureq::ErrorKind::BadHeader)
                ) {
                    format!(
                        "{msg} [medusa] hint: pass headers as Name: value pairs separated by \";\" on ONE line, e.g. \"Authorization: Bearer <token>; Content-Type: application/json\". Do NOT join headers with newlines or commas."
                    )
                } else {
                    msg
                };
                if deterministic {
                    ToolResult::error_non_retryable(
                        "medusa-http",
                        &request.capability,
                        &request.target,
                        msg,
                    )
                } else {
                    ToolResult::error(
                        "medusa-http",
                        &request.capability,
                        &request.target,
                        msg,
                    )
                }
            }
        }
    }

    fn execute_traced(
        &self,
        request: &CapabilityRequest,
        ctx: &ExecutionContext,
        trace: &mut dyn FnMut(&str, String, serde_json::Value),
    ) -> ToolResult {
        // Exact wire shape without secret values: header NAMES prove the
        // model's serialization (one blob vs two headers); body length
        // proves payload presence. Values are scrubbed at the sink anyway.
        // prepare_call failure here mirrors what execute() will report —
        // the trace shows the attempted shape either way.
        let shape = prepare_call(request).ok();
        let (method, url, names, body_len, follow) = match &shape {
            Some(p) => (
                p.method.clone(),
                redact_url(&p.url),
                p.headers.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>(),
                p.body.as_ref().map(|b| b.len()).unwrap_or(0),
                p.follow,
            ),
            None => (
                "?".to_string(),
                redact_url(&HttpRequestProvider::normalize_url(&request.target)),
                Vec::new(),
                0,
                true,
            ),
        };
        trace(
            crate::infra::trace::tag::TOOL_HTTP_CALL,
            format!("{method} {url} headers=[{}] body={body_len}b", names.join(",")),
            serde_json::json!({
                "provider": "medusa-http",
                "capability": request.capability,
                "method": method,
                "url": url,
                "header_names": names,
                "body_len": body_len,
                "follow_redirects": follow,
                "timeout_secs": self.timeout.as_secs(),
            }),
        );
        self.execute(request, ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::executor::StubExecutor;
    use crate::agent::model::OptionSet;
    use crate::agent::provider::ExecutionContext;

    fn run(target: &str, opts: OptionSet) -> ToolResult {
        let p = HttpRequestProvider::new().with_timeout(Duration::from_secs(10));
        let request = CapabilityRequest {
            capability: "api.auth_testing".into(),
            target: target.into(),
            options: opts,
            reason: "live test".into(),
        };
        let stub = StubExecutor::new();
        let env = crate::model::EnvironmentState::empty();
        let ctx = ExecutionContext {
            executor: &stub,
            env: &env,
        };
        p.execute(&request, &ctx)
    }

    #[test]
    fn malformed_url_is_non_retryable() {
        // A deterministic input error (bad URL) must be marked
        // non-retryable so the loop reports it immediately instead of
        // burning three identical retries — which is what disabled
        // api.auth_testing for the session.
        let r = run(":::bad url:::", OptionSet::new());
        assert!(!r.success());
        assert!(r.is_non_retryable(), "error should be non-retryable: {r:?}");
    }

    #[test]
    #[ignore = "live: needs a local HTTP server on 127.0.0.1:3000"]
    fn live_post_and_get_against_juice_shop() {
        let r = run(
            "http://127.0.0.1:3000/rest/admin/application-version",
            OptionSet::new(),
        );
        assert!(
            r.success(),
            "GET failed: error={:?} stdout={}",
            r.error,
            &r.stdout.chars().take(300).collect::<String>()
        );
        println!(
            "GET stdout: {}",
            &r.stdout.chars().take(300).collect::<String>()
        );

        // GET the ROOT (the exact shape the failing assessment used).
        let r = run("http://127.0.0.1:3000", OptionSet::new());
        assert!(
            r.success(),
            "GET root failed: error={:?} stdout={}",
            r.error,
            &r.stdout.chars().take(300).collect::<String>()
        );
        println!(
            "GET root: {}",
            &r.stdout.chars().take(200).collect::<String>()
        );

        // POST + JSON headers + body shape (auth testing)
        let mut opts = OptionSet::new();
        opts.insert(
            "headers".into(),
            OptionValue::Str("Content-Type: application/json".into()),
        );
        opts.insert(
            "body".into(),
            OptionValue::Str(r#"{"email":"x@y.z","password":"x"}"#.into()),
        );
        let r = run("http://127.0.0.1:3000/rest/user/login", opts);
        assert!(
            r.success(),
            "POST failed: error={:?} stdout={}",
            r.error,
            &r.stdout.chars().take(300).collect::<String>()
        );
        // 401 for bad creds is a valid observation, not a failure.
        assert!(
            r.stdout.contains("\"status\":401"),
            "stdout: {}",
            &r.stdout.chars().take(300).collect::<String>()
        );
        println!(
            "POST stdout: {}",
            &r.stdout.chars().take(300).collect::<String>()
        );

        // POST to the ROOT with the same options (auth-testing shape aimed
        // at the base URL, as the model did in the failing run).
        let mut opts = OptionSet::new();
        opts.insert("method".into(), OptionValue::Str("POST".into()));
        opts.insert(
            "headers".into(),
            OptionValue::Str("Content-Type: application/json".into()),
        );
        opts.insert(
            "body".into(),
            OptionValue::Str(r#"{"email":"x@y.z","password":"x"}"#.into()),
        );
        let r = run("http://127.0.0.1:3000", opts);
        println!(
            "POST root: success={} error={:?} stdout={}",
            r.success(),
            r.error,
            &r.stdout.chars().take(200).collect::<String>()
        );

        // follow_redirects=false shape.
        let mut opts = OptionSet::new();
        opts.insert("follow_redirects".into(), OptionValue::Bool(false));
        let r = run("http://127.0.0.1:3000", opts);
        println!(
            "no-redirect GET root: success={} error={:?}",
            r.success(),
            r.error
        );
    }

    #[test]
    #[ignore = "live: error-shape probes against a live server"]
    fn live_error_shapes_are_reported_not_panicked() {
        // No-scheme host:port target.
        let r = run("127.0.0.1:3000/rest/products/search", OptionSet::new());
        assert!(r.success(), "no-scheme failed: {:?}", r.error);
        // Malformed headers are rejected before any I/O (no panic, no
        // silent merge into one header).
        let mut opts = OptionSet::new();
        opts.insert("headers".into(), OptionValue::Str("garbage".into()));
        let r = run("http://127.0.0.1:3000/", opts);
        assert!(!r.success(), "garbage headers must be rejected");
        assert!(r.is_non_retryable(), "rejection must be deterministic");
        assert!(
            r.error.as_deref().unwrap_or("").contains("object"),
            "error must name the object format: {:?}",
            r.error
        );
        // Method with trailing space — must not corrupt the request.
        let mut opts = OptionSet::new();
        opts.insert("method".into(), OptionValue::Str("get ".into()));
        let r = run("http://127.0.0.1:3000/", opts);
        println!("spacey method: success={} error={:?}", r.success(), r.error);
    }

    #[test]
    fn option_set_contains_works_for_btree_maps() {
        let mut opts = OptionSet::new();
        opts.insert("method".into(), OptionValue::Str("POST".into()));
        assert!(opts.contains_key("method"));
        assert!(!opts.contains_key("body"));
    }

    #[test]
    fn url_normalization_adds_scheme() {
        assert_eq!(
            HttpRequestProvider::normalize_url("127.0.0.1:3000/rest/user/login"),
            "http://127.0.0.1:3000/rest/user/login"
        );
        assert_eq!(
            HttpRequestProvider::normalize_url("https://example.com/x"),
            "https://example.com/x"
        );
    }

    #[test]
    fn url_normalization_repairs_mangled_backslashes() {
        assert_eq!(
            HttpRequestProvider::normalize_url(r"http:\127.0.0.1:3000"),
            "http://127.0.0.1:3000"
        );
        assert_eq!(
            HttpRequestProvider::normalize_url(r"http:\\127.0.0.1:3000"),
            "http://127.0.0.1:3000"
        );
        assert_eq!(
            HttpRequestProvider::normalize_url(r"https:\example.com"),
            "https://example.com"
        );
        assert_eq!(
            HttpRequestProvider::normalize_url(r"http:\127.0.0.1:3000/rest/user/login"),
            "http://127.0.0.1:3000/rest/user/login"
        );
    }

    #[test]
    fn path_option_resolves_against_target_origin() {
        // Bare origin + path.
        assert_eq!(
            apply_path("http://127.0.0.1:3000", "/rest/products"),
            "http://127.0.0.1:3000/rest/products"
        );
        // Missing leading slash is tolerated.
        assert_eq!(
            apply_path("http://127.0.0.1:3000", "rest/products"),
            "http://127.0.0.1:3000/rest/products"
        );
        // A path already on the target is overridden by the option.
        assert_eq!(
            apply_path("http://127.0.0.1:3000/old/path", "/new"),
            "http://127.0.0.1:3000/new"
        );
        // Query string in the path survives.
        assert_eq!(
            apply_path("https://host:8443", "/search?q=x"),
            "https://host:8443/search?q=x"
        );
        // Empty path is a no-op.
        assert_eq!(apply_path("http://h/", ""), "http://h/");
    }

    #[test]
    fn path_option_is_accepted_end_to_end_not_rejected() {
        // Regression: the model borrows `path` from http.probe. It must be
        // accepted and folded into the URL, never rejected as unknown.
        let mut opts = OptionSet::new();
        opts.insert("path".into(), OptionValue::Str("/rest/admin".into()));
        let req = CapabilityRequest {
            capability: "http.request".into(),
            target: "http://127.0.0.1:3000".into(),
            options: opts,
            reason: "r".into(),
        };
        let prepared = prepare_call(&req).expect("path must be accepted");
        assert_eq!(prepared.url, "http://127.0.0.1:3000/rest/admin");
    }

    #[test]
    fn large_body_reports_true_length_and_pages_with_offset() {
        // A body far larger than one window: the old code hard-capped at
        // 8KB and reported body_length=8000, hiding the rest with no
        // recovery. Now the FULL length is reported and the window pages.
        let full = "0123456789".repeat(5_000); // 50_000 chars
        let ev = body_evidence("http://x/list", "GET", 200, "application/json", &full, None, 0);
        assert_eq!(ev["body_length"].as_u64().unwrap(), 50_000, "must report TRUE length");
        assert_eq!(ev["returned_chars"].as_u64().unwrap() as usize, BODY_WINDOW_CHARS);
        assert_eq!(ev["offset"].as_u64().unwrap(), 0);
        assert!(
            ev["note"].as_str().unwrap_or("").contains("more remains"),
            "a windowed body must tell the model how to page: {:?}",
            ev["note"]
        );
        // Second page starts where the first ended and reaches new content.
        let ev2 = body_evidence(
            "http://x/list",
            "GET",
            200,
            "application/json",
            &full,
            None,
            BODY_WINDOW_CHARS,
        );
        assert_eq!(ev2["offset"].as_u64().unwrap() as usize, BODY_WINDOW_CHARS);
        assert!(ev2["returned_chars"].as_u64().unwrap() > 0);
    }

    #[test]
    fn grep_jumps_to_a_match_deep_in_a_large_body() {
        // The needle sits well past the first window — unreachable under the
        // old head-only truncation; grep must land on it.
        let mut full = "A".repeat(BODY_WINDOW_CHARS * 3);
        full.push_str("\"key\":\"scoreBoardChallenge\"");
        let ev = body_evidence("http://x/c", "GET", 200, "application/json", &full, Some("scoreBoardChallenge"), 0);
        assert_eq!(ev["grep_matched"].as_bool(), Some(true));
        assert!(ev["body_snippet"].as_str().unwrap().contains("scoreBoardChallenge"));
        assert!(ev["offset"].as_u64().unwrap() as usize > BODY_WINDOW_CHARS, "window must start deep");
    }

    #[test]
    fn grep_miss_is_flagged_not_silently_empty() {
        let ev = body_evidence("http://x/c", "GET", 200, "text/plain", "hello world", Some("absent"), 0);
        assert_eq!(ev["grep_matched"].as_bool(), Some(false));
        assert!(ev["body_snippet"].as_str().unwrap().is_empty());
        assert!(ev["note"].as_str().unwrap_or("").contains("not found"));
    }

    #[test]
    fn small_body_has_no_paging_note() {
        let ev = body_evidence("http://x/", "GET", 200, "text/html", "tiny body", None, 0);
        assert_eq!(ev["body_length"].as_u64().unwrap(), 9);
        assert_eq!(ev["body_snippet"].as_str().unwrap(), "tiny body");
        assert!(ev["note"].is_null(), "a fully-returned body needs no note");
    }

    #[test]
    fn headers_map_builds_distinct_headers() {
        use std::collections::BTreeMap;
        let mut opts = OptionSet::new();
        opts.insert(
            "headers".into(),
            OptionValue::Map(
                [("Authorization", "Bearer abc123"), ("Content-Type", "application/json")]
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect::<BTreeMap<_, _>>(),
            ),
        );
        let req = CapabilityRequest {
            capability: "http.request".into(),
            target: "http://127.0.0.1:9/".into(),
            options: opts,
            reason: "test".into(),
        };
        // No network touched: prepare only.
        let p = HttpRequestProvider::new();
        let _ = p;
        let prepared = prepare_call(&req).expect("map headers must build");
        assert_eq!(prepared.headers.len(), 2);
        assert_eq!(
            prepared.headers[0],
            ("Authorization".to_string(), "Bearer abc123".to_string())
        );
        assert_eq!(
            prepared.headers[1],
            ("Content-Type".to_string(), "application/json".to_string())
        );
    }

    #[test]
    fn headers_map_rejects_bad_names_and_multiline_values() {
        use std::collections::BTreeMap;
        for (name, value) in [
            ("Bad Name", "v"),
            ("X-Ok", "a\nb"),
            ("", "v"),
        ] {
            let mut opts = OptionSet::new();
            opts.insert(
                "headers".into(),
                OptionValue::Map(
                    [(name, value)]
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect::<BTreeMap<_, _>>(),
                ),
            );
            let req = CapabilityRequest {
                capability: "http.request".into(),
                target: "http://127.0.0.1:9/".into(),
                options: opts,
                reason: "test".into(),
            };
            assert!(
                prepare_call(&req).is_err(),
                "must reject {name:?}={value:?}"
            );
        }
    }

    #[test]
    fn comma_glued_headers_are_rejected_not_merged() {
        // The observed incident: two headers glued with a comma became ONE
        // malformed Authorization header and a 401. Reject, don't merge.
        let mut opts = OptionSet::new();
        opts.insert(
            "headers".into(),
            OptionValue::Str(
                "Authorization: Bearer abc123, Content-Type: application/json".into(),
            ),
        );
        let req = CapabilityRequest {
            capability: "http.request".into(),
            target: "http://127.0.0.1:9/".into(),
            options: opts,
            reason: "test".into(),
        };
        let err = prepare_call(&req).unwrap_err();
        assert!(err.contains("object"), "{err}");
    }

    #[test]
    fn newline_joined_headers_are_rejected() {
        let mut opts = OptionSet::new();
        opts.insert(
            "headers".into(),
            OptionValue::Str("Authorization: Bearer abc123\nContent-Type: application/json".into()),
        );
        let req = CapabilityRequest {
            capability: "http.request".into(),
            target: "http://127.0.0.1:9/".into(),
            options: opts,
            reason: "test".into(),
        };
        let err = prepare_call(&req).unwrap_err();
        assert!(err.contains("object"), "{err}");
    }

    #[test]
    fn body_without_content_type_is_rejected() {
        use std::collections::BTreeMap;
        let mut opts = OptionSet::new();
        opts.insert(
            "headers".into(),
            OptionValue::Map(
                [("Authorization", "Bearer abc123")]
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect::<BTreeMap<_, _>>(),
            ),
        );
        opts.insert("body".into(), OptionValue::Str(r#"{"a":1}"#.into()));
        let req = CapabilityRequest {
            capability: "http.request".into(),
            target: "http://127.0.0.1:9/".into(),
            options: opts,
            reason: "test".into(),
        };
        let err = prepare_call(&req).unwrap_err();
        assert!(err.contains("Content-Type"), "{err}");
    }

    #[test]
    fn provider_identity_and_availability() {
        let p = HttpRequestProvider::new();
        assert_eq!(p.id(), "medusa-http");
        assert!(p
            .capabilities()
            .iter()
            .all(|c| HTTP_CAPABILITIES.contains(&c.as_str())));
        assert!(p.is_available(&crate::model::EnvironmentState::empty()));
        assert!(p.supports_option("http.request", "method"));
        assert!(!p.supports_option("http.request", "bogus"));
    }
}
