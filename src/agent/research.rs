//! Internal web-research provider (`medusa-research`): lets the model
//! fetch and read web content — documentation, code, web scraping —
//! to validate findings, research CVEs, and understand targets.
//!
//! Design:
//! * **Read-only**: this capability only fetches and extracts text. It
//!   can never launch an attack tool at a researched target. The executor
//!   it drives is scoped to fetching; anything requiring exploitation is
//!   a separate, policy-gated capability.
//! * **URL-driven**: the model names a URL (a GitHub repo, a docs root,
//!   any page) that the provider fetches and extracts. Search is NOT
//!   part of this capability — the model searches via the direct
//!   `web_search` decision (see `agent::web_search`) and reads the hits
//!   here.
//! * **Open access by operator choice**: research may read any URL. This
//!   is intentional and explicit — research reads, it does not attack.
//!
//! Fetch+extract is built in via ureq (already the model-transport HTTP
//! client).

use std::time::Duration;

use super::executor::ToolResult;
use super::provider::{CapabilityProvider, CapabilityRequest, ExecutionContext};

pub const RESEARCH_CAPABILITIES: [&str; 1] = ["web.research"];

/// Width of the window returned to the model per fetch (chars). The full
/// page is extracted internally; `grep`/`offset` choose WHICH window of it
/// rides the evidence, so content past this width is reachable without a
/// bigger context cost.
const EXTRACT_CHARS: usize = 12_000;
/// Chars kept BEFORE a `grep` match so the matched line has leading
/// context (the match rarely wants to sit on the very first line).
const GREP_LEAD_CHARS: usize = 400;
/// Cap on an individual fetched page body before extraction.
const FETCH_CAP_BYTES: usize = 2 * 1024 * 1024;
/// Default fetch timeout.
const FETCH_TIMEOUT: Duration = Duration::from_secs(20);

pub struct ResearchProvider {
    timeout: Duration,
}

impl Default for ResearchProvider {
    fn default() -> Self {
        Self { timeout: FETCH_TIMEOUT }
    }
}

impl ResearchProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Extract readable text from HTML: drop scripts/styles/tags, collapse
/// whitespace, prefer headers and code blocks. Good enough for research
/// without pulling in a full HTML engine.
fn html_to_text(html: &str) -> String {
    // Guard against pathological inputs.
    let html: String = html.chars().take(FETCH_CAP_BYTES).collect();
    // Drop script/style blocks entirely.
    let without_scripts = strip_blocks(&html, &["script", "style", "noscript", "svg", "head"]);
    let mut out = String::with_capacity(without_scripts.len());
    // Inline text replacing tags with separators so words don't jam.
    let mut in_tag = false;
    let mut skip_tag = String::new();
    for ch in without_scripts.chars() {
        if in_tag {
            if ch == '>' {
                in_tag = false;
                // code/pre/br produce a newline so neighboring text separates.
                if matches!(
                    skip_tag.as_str(),
                    "p" | "div"
                        | "br"
                        | "li"
                        | "h1"
                        | "h2"
                        | "h3"
                        | "h4"
                        | "pre"
                        | "code"
                        | "tr"
                        | "section"
                        | "article"
                ) {
                    out.push('\n');
                }
                skip_tag = String::new();
            } else if !ch.is_whitespace() {
                skip_tag.push(ch);
            }
            continue;
        }
        if ch == '<' {
            in_tag = true;
            skip_tag = String::new();
            continue;
        }
        out.push(ch);
    }
    // Collapse runs of whitespace.
    let mut result = String::with_capacity(out.len());
    let mut ws = true;
    for ch in out.chars() {
        if ch.is_whitespace() {
            if !ws {
                result.push(' ');
            }
            ws = true;
        } else {
            result.push(ch);
            ws = false;
        }
    }
    // Full extracted text (bounded only by the fetch cap). Windowing to
    // EXTRACT_CHARS happens in `window_text` so grep/offset can reach
    // content past the first window.
    result.trim().to_string()
}

/// Outcome of windowing the full extract down to what rides the evidence.
/// Shared with `http_provider` so a large HTTP body pages the same way a
/// large research extract does (grep/offset), instead of hard-truncating.
pub(crate) struct Window {
    /// The slice returned to the model.
    pub(crate) text: String,
    /// Length of the FULL extract (so the model knows how much it skipped).
    pub(crate) total_chars: usize,
    /// Char offset the returned slice starts at.
    pub(crate) offset: usize,
    /// Set when a `grep` was requested: whether it matched.
    pub(crate) grep_matched: Option<bool>,
}

/// Select a `width`-wide window to return. With `grep`, center on the first
/// case-insensitive match (with lead context); otherwise start at `offset`.
/// Char-boundary safe. A non-matching grep returns an empty slice flagged
/// `grep_matched: Some(false)` so the model knows to try a different pattern
/// rather than assuming the content is absent. Shared by `http_provider`.
pub(crate) fn window_text(full: &str, grep: Option<&str>, offset: usize, width: usize) -> Window {
    let chars: Vec<char> = full.chars().collect();
    let total = chars.len();
    if let Some(pat) = grep.map(str::trim).filter(|p| !p.is_empty()) {
        let hay = full.to_lowercase();
        let needle = pat.to_lowercase();
        match hay.find(&needle) {
            Some(byte_idx) => {
                // Translate the byte index into a char index.
                let char_idx = full[..byte_idx].chars().count();
                let start = char_idx.saturating_sub(GREP_LEAD_CHARS);
                let end = (start + width).min(total);
                Window {
                    text: chars[start..end].iter().collect(),
                    total_chars: total,
                    offset: start,
                    grep_matched: Some(true),
                }
            }
            None => Window {
                text: String::new(),
                total_chars: total,
                offset: 0,
                grep_matched: Some(false),
            },
        }
    } else {
        let start = offset.min(total);
        let end = (start + width).min(total);
        Window {
            text: chars[start..end].iter().collect(),
            total_chars: total,
            offset: start,
            grep_matched: None,
        }
    }
}

/// Replace `script`/`style` blocks (with their inner text) with a space,
/// so their content doesn't leak into the readable extract.
fn strip_blocks(html: &str, tags: &[&str]) -> String {
    let mut out = String::with_capacity(html.len());
    let lower = html.to_lowercase();
    let mut i = 0usize;
    while i < html.len() {
        // Find next "<tag".
        let mut consumed = false;
        for tag in tags {
            let open = format!("<{tag}");
            let close = format!("</{tag}>");
            if lower[i..].starts_with(&open) {
                if let Some(c) = lower[i..].find(&close) {
                    i += c + close.len();
                    out.push(' ');
                    consumed = true;
                    break;
                }
            }
        }
        if consumed {
            continue;
        }
        // fall through copying chars
        let ch = html[i..].chars().next().unwrap_or(' ');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn fetch_text(
    url: &str,
    grep: Option<&str>,
    offset: usize,
    timeout: Duration,
) -> Result<ToolResult, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(timeout)
        .user_agent("Cipher/0.1 (security-research; contact local-operator)")
        .build();
    let resp = agent.get(url).call().map_err(|e| format!("fetch failed: {e}"))?;
    let status = resp.status();
    let content_type = resp.content_type().to_string();
    let mut body = Vec::with_capacity(64 * 1024);
    use std::io::Read;
    let mut reader = resp.into_reader().take(FETCH_CAP_BYTES as u64);
    reader.read_to_end(&mut body).map_err(|e| format!("read failed: {e}"))?;
    let body_str = String::from_utf8_lossy(&body);
    let is_html = content_type.contains("html");
    // Full extract first, then window it — so grep/offset can reach past
    // the first EXTRACT_CHARS of a large file instead of only its head.
    let full = if is_html {
        html_to_text(&body_str)
    } else {
        body_str.trim().to_string()
    };
    let win = window_text(&full, grep, offset, EXTRACT_CHARS);
    let mut evidence = serde_json::json!({
        "url": url,
        "status": status,
        "content_type": content_type,
        "total_chars": win.total_chars,
        "offset": win.offset,
        "returned_chars": win.text.chars().count(),
        "text": win.text,
    });
    if let Some(matched) = win.grep_matched {
        evidence["grep"] = serde_json::json!(grep.unwrap_or("").trim());
        evidence["grep_matched"] = serde_json::json!(matched);
        if !matched {
            evidence["note"] = serde_json::json!(
                "grep pattern not found in the extract — try a different/shorter pattern, or omit grep and use offset to page through"
            );
        }
    } else if win.offset + win.text.chars().count() < win.total_chars {
        // More content remains past this window: tell the model how to get it.
        evidence["note"] = serde_json::json!(format!(
            "{} of {} chars shown from offset {}; more remains — pass grep=<text> to jump to a section, or offset={} to continue",
            win.text.chars().count(),
            win.total_chars,
            win.offset,
            win.offset + win.text.chars().count()
        ));
    }
    let stdout = serde_json::to_string(&evidence).unwrap_or_default();
    Ok(ToolResult {
        tool_id: "medusa-research".to_string(),
        capability: "web.research".to_string(),
        target: url.to_string(),
        exit_code: 0,
        stdout,
        stderr: String::new(),
        timed_out: false,
        error: None,
    })
}

impl CapabilityProvider for ResearchProvider {
    fn id(&self) -> &str {
        "medusa-research"
    }

    fn capabilities(&self) -> &[String] {
        static CAPS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
        CAPS.get_or_init(|| RESEARCH_CAPABILITIES.iter().map(|s| s.to_string()).collect())
    }

    fn priority(&self) -> u8 {
        30
    }

    fn supports_option(&self, _capability: &str, option: &str) -> bool {
        matches!(option, "selector" | "grep" | "offset")
    }

    fn is_available(&self, _env: &crate::model::EnvironmentState) -> bool {
        true // built-in, no external executable
    }

    fn execute(&self, request: &CapabilityRequest, _ctx: &ExecutionContext) -> ToolResult {
        // The request target is the URL to read. `grep`/`offset` window the
        // extract so large files are reachable past the first page;
        // `selector` is accepted but not yet used (whole-page extraction).
        let target = request.target.trim();
        if target.is_empty() {
            return ToolResult::error_non_retryable(
                "medusa-research",
                &request.capability,
                "",
                "web.research requires a target URL".into(),
            );
        }
        let grep = match request.options.get("grep") {
            Some(crate::agent::model::OptionValue::Str(s)) => Some(s.clone()),
            _ => None,
        };
        let offset = match request.options.get("offset") {
            Some(crate::agent::model::OptionValue::Num(n)) if *n >= 0.0 => *n as usize,
            _ => 0,
        };
        match fetch_text(target, grep.as_deref(), offset, self.timeout) {
            Ok(res) => res,
            Err(e) => ToolResult::error_non_retryable(
                "medusa-research",
                &request.capability,
                &request.target,
                e,
            ),
        }
    }

    fn execute_traced(
        &self,
        request: &CapabilityRequest,
        ctx: &ExecutionContext,
        trace: &mut dyn FnMut(&str, String, serde_json::Value),
    ) -> ToolResult {
        trace(
            crate::infra::trace::tag::TOOL_RESEARCH,
            format!("fetch {}", request.target.chars().take(120).collect::<String>()),
            serde_json::json!({
                "provider": "medusa-research",
                "capability": request.capability,
                "target_len": request.target.len(),
                "timeout_secs": self.timeout.as_secs(),
            }),
        );
        self.execute(request, ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_extraction_drops_tags_and_scripts() {
        let html = "<html><head><title>t</title></head><body><script>alert(1)</script><h1>Heading</h1><p>Hello <b>world</b></p><pre>code();</pre></body></html>";
        let text = html_to_text(html);
        assert!(text.contains("Heading"));
        assert!(text.contains("Hello world"));
        assert!(text.contains("code();"));
        assert!(!text.contains("alert(1)"));
        assert!(!text.contains("<h1>"));
    }

    #[test]
    fn grep_jumps_to_a_match_deep_in_a_large_extract() {
        // A body far larger than one window, with the needle well past the
        // first EXTRACT_CHARS — the old head-only extract could never reach
        // it; grep must.
        let mut full = "A".repeat(EXTRACT_CHARS * 2);
        full.push_str("NEEDLE_svgInjectionChallenge_here");
        full.push_str(&"B".repeat(500));
        let win = window_text(&full, Some("svgInjectionChallenge"), 0, EXTRACT_CHARS);
        assert_eq!(win.grep_matched, Some(true));
        assert!(win.text.contains("svgInjectionChallenge"), "window must contain the match");
        assert!(win.offset > EXTRACT_CHARS, "window must start deep in the file, got {}", win.offset);
        assert!(win.text.chars().count() <= EXTRACT_CHARS);
    }

    #[test]
    fn grep_miss_is_flagged_not_silently_empty() {
        let win = window_text("hello world", Some("notpresent"), 0, EXTRACT_CHARS);
        assert_eq!(win.grep_matched, Some(false));
        assert!(win.text.is_empty());
    }

    #[test]
    fn offset_pages_through_and_reports_total() {
        let full = "0123456789".repeat(2000); // 20_000 chars
        let first = window_text(&full, None, 0, EXTRACT_CHARS);
        assert_eq!(first.total_chars, 20_000);
        assert_eq!(first.offset, 0);
        assert_eq!(first.text.chars().count(), EXTRACT_CHARS);
        // Second page starts where the first ended and reaches new content.
        let second = window_text(&full, None, EXTRACT_CHARS, EXTRACT_CHARS);
        assert_eq!(second.offset, EXTRACT_CHARS);
        assert!(second.text.chars().count() > 0);
        assert!(second.grep_matched.is_none());
    }

    #[test]
    fn empty_target_is_non_retryable() {
        let p = ResearchProvider::new();
        let req = CapabilityRequest {
            capability: "web.research".into(),
            target: "".into(),
            options: super::super::model::OptionSet::new(),
            reason: "r".into(),
        };
        let stub = super::super::executor::StubExecutor::new();
        let env = crate::model::EnvironmentState::empty();
        let ctx = ExecutionContext { executor: &stub, env: &env };
        let r = p.execute(&req, &ctx);
        assert!(r.is_non_retryable());
    }
}