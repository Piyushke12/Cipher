//! Rich inline investigation UI (Phase 1.6).
//!
//! Renders the [`AgentEvent`] stream with colors (`console`) and a thinking
//! spinner (`indicatif`). No hand-rolled escape sequences; output degrades to
//! plain text when piped. The full-screen ratatui UI will consume the same
//! event stream later.

use console::style;
use indicatif::{ProgressBar, ProgressDrawTarget};

use crate::agent::{
    AgentEvent, AgentRuntime, AssessmentState, CliProvider, Decision, FinishReason,
    InvestigationResult, ModelProvider, OpenAiCompatibleProvider, OptionSet, ProviderRegistry,
    StubProvider, Target,
};
use crate::infra::trace::{TraceEntry, TraceWriter};
use crate::model::EnvironmentState;
use crate::registry::{CapabilityRegistry, ToolRegistry};

/// Spinner wrapper: started on `ModelThinking`, cleared by the next event.
struct Spinner {
    bar: Option<ProgressBar>,
}

impl Spinner {
    fn start(&mut self, msg: &str) {
        self.stop();
        let bar = ProgressBar::new_spinner();
        bar.set_draw_target(ProgressDrawTarget::stderr());
        bar.set_message(msg.to_string());
        bar.enable_steady_tick(std::time::Duration::from_millis(80));
        self.bar = Some(bar);
    }

    fn stop(&mut self) {
        if let Some(bar) = self.bar.take() {
            bar.finish_and_clear();
        }
    }
}

pub struct EventRenderer {
    spinner: Spinner,
}

impl EventRenderer {
    pub fn new() -> Self {
        Self {
            spinner: Spinner { bar: None },
        }
    }

    pub fn on_event(&mut self, ev: &AgentEvent) {
        // Any real event supersedes the thinking spinner.
        if !matches!(ev, AgentEvent::ModelThinking) {
            self.spinner.stop();
        }
        match ev {
            AgentEvent::InvestigationStarted { target } => {
                println!(
                    "\n{}",
                    style(format!("Cipher — investigating {target}"))
                        .cyan()
                        .bold()
                );
                println!("{}", style("â”€".repeat(45)).dim());
            }
            AgentEvent::StepStarted { step } => {
                println!("{}", style(format!("Step {}", step + 1)).dim());
            }
            AgentEvent::ModelThinking => {
                self.spinner.start("Agent thinking…");
            }
            AgentEvent::ScopeGranted { target } => {
                println!("{}", style(format!("Scope: {target}")).dim());
            }
            AgentEvent::Reply { text } => {
                // Autonomous runs have no user; replies surface as narration.
                println!("\n{text}\n");
            }
            AgentEvent::Narrated { text } => {
                println!("\n{text}\n");
            }
            AgentEvent::UserMessageSeen { text } => {
                println!("{}", style(format!("You: {text}")).cyan());
            }
            AgentEvent::CapabilityRequested {
                capability,
                target,
                reason,
                ..
            } => {
                // Verbal preamble (codex parity): show reason as agent thinking before tool, not just dim.
                if !reason.is_empty() {
                    println!("  {}", style(format!("â–£ thinking: {reason}")).cyan());
                }
                println!("  â””â”€ {capability} on {target}");
            }
            AgentEvent::ProviderSelected {
                capability,
                provider,
            } => {
                println!(
                    "     â””â”€ {}",
                    style(format!("{provider} selected for {capability}")).green()
                );
            }
            AgentEvent::ToolStarted {
                capability,
                provider,
            } => {
                println!("     â””â”€ executing {capability} via {provider}…");
            }
            AgentEvent::ToolFinished {
                capability,
                provider,
            } => {
                println!("     â””â”€ {capability} via {provider} done");
            }
            AgentEvent::ToolExecuted {
                tool_id,
                capability,
                target,
                exit_code,
                success,
                timed_out,
                output: _,
                ..
            } => {
                let status = if *timed_out {
                    "timed out"
                } else if *success {
                    "ok"
                } else {
                    "failed"
                };
                println!(
                    "     â””â”€ {tool_id} on {target} [{capability}] exit={exit_code} {status}"
                );
            }
            AgentEvent::ObservationAdded { summary } => {
                println!("  {} {summary}", style("â—‹").cyan());
            }
            AgentEvent::HypothesisAdded {
                id,
                statement,
                confidence,
            } => {
                println!(
                    "  {}",
                    style(format!("H{id} [{confidence}]: {statement}")).yellow()
                );
            }
            AgentEvent::ActionRejected { reason } => {
                println!(
                    "  {} {}",
                    style("? rejected:").red().bold(),
                    style(reason).red()
                );
            }
            AgentEvent::ApprovalRequested { capability, reason } => {
                println!(
                    "  {} {} — {}",
                    style("! approval:").yellow().bold(),
                    style(capability).yellow(),
                    style(reason).yellow()
                );
            }
            AgentEvent::Finished { reason } => {
                println!("{}", style(format!("Finished: {reason}")).bold());
            }
            AgentEvent::Error { message } => {
                eprintln!("  {} {}", style("!").red().bold(), style(message).red());
            }
            AgentEvent::Status { message } => {
                println!("  {} {}", style("~").dim().bold(), style(message).dim());
            }
            AgentEvent::FindingRecorded {
                id,
                severity,
                title,
                target,
                status,
                ..
            } => {                println!(
                    "  {}",
                    style(format!("F{id} [{severity}/{status}] {title} ({target})")).bold()
                );
            }
            AgentEvent::ContextUsage {
                used_tokens,
                limit_tokens,
                pct,
                estimated,
                cached_tokens,
            } => {
                println!(
                    "  {}",
                    style(format!(
                        "context {used_tokens}/{limit_tokens} ({pct}%){}{}",
                        if *estimated { " (est.)" } else { "" },
                        if *cached_tokens > 0 {
                            format!(" [{} cached]", cached_tokens)
                        } else {
                            String::new()
                        }
                    ))
                    .dim()
                );
            }
            AgentEvent::Compacted {
                before_tokens,
                after_tokens,
                freed_tokens,
                fallback,
            } => {
                println!(
                    "  {}",
                    style(format!(
                        "compacted{}: {before_tokens} → {after_tokens} (freed {freed_tokens})",
                        if *fallback { " (fallback)" } else { "" }
                    ))
                    .yellow()
                );
            }
            AgentEvent::VaultStored { key, kind, refreshed } => {
                println!(
                    "  {}",
                    style(format!(
                        "vault: {key} [{kind}] {}",
                        if *refreshed { "refreshed" } else { "stored" }
                    ))
                    .dim()
                );
            }
            AgentEvent::VaultRecalled { key } => {
                println!("  {}", style(format!("vault: recalled {key}")).dim());
            }
            AgentEvent::HypothesisCreated { statement, family } => {
                println!("  {}", style(format!("hypothesis [{family}]: {statement}")).yellow());
            }
            AgentEvent::FindingUpdated { id, stage, note } => {
                println!("  {}", style(format!("finding {id} -> {stage}: {note}")).bold());
            }
            AgentEvent::AttackGraphUpdated { nodes, edges, newly_reachable } => {
                println!("  {}", style(format!("attack graph: {nodes} nodes / {edges} edges; new: {}", newly_reachable.join(", "))).dim());
            }
            AgentEvent::SecurityTestProgressUpdated { family, status } => {
                println!("  {}", style(format!("family {family}: {status}")).dim());
            }
            AgentEvent::CompletionEvaluated { allowed, reason, remaining } => {
                println!("  {}", style(format!("completion: {} ({reason}, {remaining} remaining)", if *allowed { "allowed" } else { "rejected" })).dim());
            }
            AgentEvent::ActionBlocked { reason } => {
                println!("  {} {}", style("! blocked:").red().bold(), style(reason).red());
            }
        }
    }

    pub fn summary(&mut self, res: &InvestigationResult) {
        self.summary_with_state(res, None);
    }

    /// Summary plus authoritative assessment views (families, findings,
    /// attack path, identity/privilege, unknowns, completion). All data
    /// comes from runtime state, never hardcoded UI data.
    pub fn summary_with_state(
        &mut self,
        res: &InvestigationResult,
        assessment: Option<&AssessmentState>,
    ) {
        self.spinner.stop();
        println!("\n{}", style("Investigation summary").bold());
        println!("  steps: {}", res.steps_taken);
        println!("  finish: {}", finish_text(&res.finish_reason));
        if let Some(err) = &res.model_error {
            println!("  model error: {}", style(err).red());
        }
        println!("  planned actions (validated, NOT executed — execution is Phase 4):");
        if res.planned_actions.is_empty() {
            println!("    (none)");
        }
        for a in &res.planned_actions {
            println!(
                "    {} {} via {} on {}",
                style("•").green(),
                a.capability,
                a.provider,
                a.target
            );
        }
        if let Some(state) = assessment {
            render_assessment_summary(state);
        }
    }
}

/// Render families / findings / attack path / identity / unknowns /
/// completion from authoritative runtime state.
pub fn render_assessment_summary(state: &AssessmentState) {
    print!("{}", assessment_summary_text(state));
}

/// Same content as [`render_assessment_summary`] as a string (TUI/workers).
pub fn assessment_summary_text(state: &AssessmentState) -> String {
    use crate::agent::completeness::AssessmentStatus;
    let mut out = String::new();
    out.push_str("\nAssessment\n");
    let (hosts, ports, endpoints, params) = state.target_model.counts();
    out.push_str(&format!("  attack surface: {hosts} hosts / {ports} ports / {endpoints} endpoints / {params} params\n"));
    if let Some(id) = &state.target_model.current_identity {
        out.push_str(&format!("  identity: {id}\n"));
    }
    out.push_str("\nVulnerability Families\n");
    if state.family_progress.is_empty() {
        out.push_str("    (no family progress tracked)\n");
    }
    for p in &state.family_progress {
        let mark = match p.status {
            AssessmentStatus::ConfirmedFinding => "✓",
            AssessmentStatus::Tested => "✓",
            AssessmentStatus::InProgress => "~",
            AssessmentStatus::NotStarted => "○",
            AssessmentStatus::Blocked => "!",
            AssessmentStatus::NotApplicable => "-",
        };
        out.push_str(&format!(
            "    {mark} {}  {}/{} questions, {} evidence\n",
            p.family, p.tested_questions, p.total_questions, p.evidence_count
        ));
    }
    out.push_str("\nFindings\n");
    if state.findings.findings.is_empty() {
        out.push_str("    (none)\n");
    }
    for f in &state.findings.findings {
        out.push_str(&format!(
            "    ◆ F{} [{:?}] {} ({}) severity={} evidence={}\n",
            f.id,
            f.stage,
            f.title,
            f.target,
            f.severity,
            f.evidence_ids.len()
        ));
    }
    out.push_str("\nAttack Path\n");
    let privs: Vec<String> = state
        .attack_graph
        .privileges()
        .iter()
        .map(|n| n.label.clone())
        .collect();
    if privs.is_empty() && state.attack_graph.nodes.is_empty() {
        out.push_str("    (no attack graph nodes yet)\n");
    } else {
        if !privs.is_empty() {
            out.push_str(&format!("    privileges: {}\n", privs.join(", ")));
        }
        // Longest known directed chain ending at a privilege/resource.
        let mut shown = false;
        let nodes: Vec<String> = state.attack_graph.nodes.keys().cloned().collect();
        'outer: for from in &nodes {
            for to in &nodes {
                if let Some(path) = state.attack_graph.path(from, to) {
                    if path.len() >= 3 {
                        out.push_str(&format!("    {}\n", path.join("\n    ↓\n    ")));
                        shown = true;
                        break 'outer;
                    }
                }
            }
        }
        if !shown {
            out.push_str(&format!(
                "    nodes={} edges={}\n",
                state.attack_graph.nodes.len(),
                state.attack_graph.edges.len()
            ));
        }
    }
    out.push_str("\nUnknowns\n");
    let unknowns = state.investigation.unresolved_high_value(70);
    if unknowns.is_empty() {
        out.push_str("    (none high-value)\n");
    }
    for o in unknowns.iter().take(8) {
        out.push_str(&format!(
            "    ? [{}] {} (via {})\n",
            o.family,
            o.question,
            o.resolving_capability.as_deref().unwrap_or("reasoning")
        ));
    }
    out.push_str(&format!(
        "\nCompletion: {} families tracked, {} evidence records, snapshot `{}`\n",
        state.family_progress.len(),
        state.evidence.records.len(),
        state.id
    ));
    out
}

impl Default for EventRenderer {
    fn default() -> Self {
        Self::new()
    }
}

fn finish_text(reason: &FinishReason) -> String {
    match reason {
        FinishReason::ModelFinished(r) => r.clone(),
        FinishReason::MaxSteps(n) => format!("max steps ({n})"),
        FinishReason::Cancelled => "cancelled".to_string(),
        FinishReason::TooManyModelErrors { count, last_error } => {
            format!("model failed {count} times in a row: {last_error}")
        }
        FinishReason::ConfigError(e) => format!("misconfigured: {e}"),
        FinishReason::ContextExhausted => {
            "context exhausted even after compaction — findings and vault kept".to_string()
        }
    }
}

/// Demo script used when no model endpoint is configured: one valid execute,
/// one deliberate rejection, one hypothesis. Real provider when env is set.
fn demo_script(state: &EnvironmentState) -> Vec<Decision> {
    let mut script = Vec::new();
    if state
        .available_capabilities()
        .contains(&"network.port_scan")
    {
        script.push(Decision::Execute {
            capability: "network.port_scan".into(),
            target: "127.0.0.1".into(),
            options: OptionSet::new(),
            reason: "demo: show provider resolution".into(),
        });
    }
    script.push(Decision::CreateHypothesis {
        statement: "demo hypothesis: external surface unknown".into(),
        confidence: "low".into(),
    });
    script
}

fn print_capability_table(state: &EnvironmentState, tools: &ToolRegistry) {
    let providers = ProviderRegistry::from_tools(tools);
    let mut available: Vec<String> = state
        .available_capabilities()
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    available.sort();
    println!("{}", style("Capabilities").bold());
    if available.is_empty() {
        println!("  (none available — install tools first, see /install)");
    }
    for cap in &available {
        // Provider resolution as the runtime would do it: capability â†’
        // best healthy provider (policy/scope do not apply to display).
        match providers.select(cap, &OptionSet::new(), state) {
            Ok(p) => println!(
                "  {} {cap} {} {}",
                style("âœ“").green(),
                style("â†’").dim(),
                p.id()
            ),
            Err(_) => println!("  {} {cap} (no healthy provider)", style("~").yellow()),
        }
    }
    let missing = state.unavailable_capabilities().len();
    println!(
        "  {}",
        style(format!("âœ— {missing} capabilities unavailable",)).dim()
    );
}

/// Model selection shared by inline (`/assess`) and fullscreen (`/tui`) UI.
/// Real provider when file/env config resolves, otherwise the offline demo.
pub fn select_model(state: &EnvironmentState) -> (Box<dyn ModelProvider>, String) {
    match crate::infra::resolve_model_config(&crate::infra::load_file_config()) {
        Ok(crate::infra::ModelBackend::Http(cfg)) => {
            let base = cfg.base_url.clone();
            let p = OpenAiCompatibleProvider::new(cfg);
            let label = format!("{} ({base})", p.name());
            (Box::new(p), label)
        }
        Ok(crate::infra::ModelBackend::Cli(cfg)) => {
            let p = CliProvider::new(
                cfg.exe.clone(),
                cfg.args.clone(),
                cfg.label.clone(),
                cfg.timeout_secs,
                cfg.stdin_prompt,
            );
            let label = format!("{} (local harness `{}`)", p.name(), cfg.exe);
            (Box::new(p), label)
        }
        Err(_) => (
            Box::new(StubProvider::new(demo_script(state))),
            "stub (demo — no model configured)".to_string(),
        ),
    }
}

/// File-only debug trace sink for CLI/TUI runs (no drawer there — the
/// JSONL file is the UI). Returns the trace id plus an append closure for
/// `AgentRuntime::with_tracer`. Best-effort: falls back to a temp file.
pub fn cli_tracer(prefix: &str) -> (String, impl FnMut(TraceEntry) + Send) {
    let id = format!(
        "{prefix}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    );
    let writer = TraceWriter::open(&id).unwrap_or_else(|_| {
        TraceWriter::open_in(&std::env::temp_dir(), &format!("trace-fallback-{id}"))
            .expect("temp trace writer")
    });
    // The id doubles as documentation of where the file went; the writer
    // owns the handle inside the returned closure.
    let mut writer = writer;
    (
        id,
        move |entry: TraceEntry| {
            writer.append(&entry);
        },
    )
}

/// Entry point for `/assess <target>`. Picks the real model when
/// `MEDUSA_MODEL_*` is configured, otherwise the offline demo script.
pub fn run_assessment(
    target: &str,
    state: &EnvironmentState,
    tools: &ToolRegistry,
    caps: &CapabilityRegistry,
) {
    println!("\n{}", style("Target").bold());
    println!("  {target}");
    print_capability_table(state, tools);

    let (model, label) = select_model(state);
    if label.starts_with("stub") {
        println!("Model: {}", style(label).dim());
        println!("  {}", style(crate::infra::config_location_help()).dim());
    } else {
        println!("Model: {label}");
    }

    println!("\n{}", style("Investigation").bold());
    let rt = AgentRuntime::new(model, tools, caps, state);
    let mut ui = EventRenderer::new();
    let (trace_id, tracer) = cli_tracer("cli");
    println!(
        "  {}",
        style(format!("trace: <state-dir>/sessions/{trace_id}.trace.jsonl")).dim()
    );
    let rt = rt.with_tracer(tracer);
    let (res, assessment) =
        rt.investigate_with_state(Target::new(target), &mut |ev| ui.on_event(&ev));
    ui.summary_with_state(&res, Some(&assessment));
}
