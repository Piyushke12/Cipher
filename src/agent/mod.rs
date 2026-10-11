//! The agent: one LLM-driven loop per session.
//!
//! The model owns the investigation (planning, methodology, what is still
//! unknown); the runtime owns the trusted boundary (scope, risk, argv,
//! execution, retries, context budgeting, persistence). Scan-specific
//! knowledge lives in tool parsers, never here.

pub mod assessment;
pub mod attack_graph;
pub mod completeness;
pub mod context;
pub mod evidence;
pub mod events;
pub mod executor;
pub mod failure;
pub mod families;
pub mod file_tools;
pub mod findings;
pub mod http_headers;
pub mod http_provider;
pub mod investigation;
pub mod model;
pub mod parsers;
pub mod planner;
pub mod policy;
pub mod provider;
pub mod research;
pub mod runtime;
pub mod security_tests;
pub mod target_model;
pub mod vault;
pub mod web_search;

pub use assessment::AssessmentState;
pub use context::{ActionRecord, BudgetReport, ContextManager, Finding, Observation, TokenBudget};
pub use events::AgentEvent;
pub use executor::{
    LocalProcessExecutor, ProcessExecutor, ProcessOutput, StubExecutor, ToolResult,
};
pub use http_provider::HttpRequestProvider;
pub use research::{RESEARCH_CAPABILITIES, ResearchProvider};

pub use model::{
    CliProvider, ContextView, Decision, ModelError, ModelProvider, OpenAiCompatibleProvider,
    OptionSet, OptionValue, StubProvider,
};
pub use parsers::{parse_tool_output, ParsedObservation};
pub use policy::{ExecutionPolicy, PolicyError, ScopePolicy};
pub use provider::{
    CapabilityProvider, CapabilityRequest, ExecutionContext, ProcessProvider, ProviderError,
    ProviderRegistry,
};
pub use runtime::{
    AgentRuntime, AgentSession, DriveOutcome, FinishReason, InvestigationResult, PlannedAction,
    RuntimeHandle, Target, assessment_id_for_target,
};
pub use vault::{VaultEntry, VaultManager};
