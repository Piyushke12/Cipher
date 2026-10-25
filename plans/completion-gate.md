# Completion gate for security assessments (coverage + finding tools)

## Context

Cipher (this OpenCode fork) can currently self-report an assessment as "complete" with no check beyond the model's own say-so — this already caused a real miss (the Memory Bomb/YAML-bomb challenge went unsolved while the session declared success based on 3 unrelated findings). There is no ground-truth oracle on real targets, so a completion check can't verify "did we find the right answer." It can only verify two things that don't require foreknowledge:

1. Every discovered attack-surface item has an explicit disposition (not silently skipped).
2. Every finding marked "confirmed" is independently reproducible right now, via a deterministic replay — not just trusted from the model's first pass.

This plan adds exactly those two checks as a harness-level gate, without adding a second agentic loop, a new database table, or touching the core step/outcome machinery.

## Architecture it hooks into (confirmed by exploration)

- Completion is inferred, not signaled: `needsContinuation` is computed in `packages/core/src/session/runner/publish-llm-event.ts:650` and resolved in `Outcome.Completed` inside `runStep`, `packages/core/src/session/runner/llm.ts` (~lines 275–283). When `!needsContinuation` and the inbox is empty, `drain()` returns `DrainResult.Complete()` and the session goes idle.
- `llm.ts` already injects synthetic continuation text for other cases (`CONTINUE_AFTER_INCOMPLETE_STREAM`, `CONTINUE_AFTER_OUTPUT_LIMIT`, `MAX_STEPS_PROMPT`) via `bus.publish(SessionEvent.Synthetic, { sessionID, text })` — the gate reuses this exact mechanism, not a new one.
- Tool registration pattern is consistent across `http.ts`, `surface.ts`, `todo.ts`: `Plugin = { id, effect: Effect.fn(...)(function*(ctx) { ... ctx.tool.transform((editor) => editor.add({ name, options, description, input: Input, output: Output, execute })) }) }`.
- `packages/core/src/tool/plugin/todo.ts` (`todowrite`) is the closest existing analog: a whole-list-replace tool, gated by an `experimental` config flag, with no separate durable table — state is just the latest tool call's `metadata` in the message stream, read back by scanning history.
- `http.ts` already has the exact HTTP-replay primitives needed (`HttpClientRequest.make/setHeaders/bodyText`, `collectBoundedResponseBody` from `tool/http-body.ts`).

## What gets built

**1. `coverage` tool** — `packages/core/src/tool/plugin/security/coverage.ts` (+ `coverage.txt` description), todowrite-shaped. Model records every discovered endpoint/param/sink with a **required** (non-optional) `disposition`: `"untested" | "tested-clean" | "confirmed-vulnerable" | "blocked-by-defense" | "not-reached"`. Because the field is required, not defaulted, the model can never leave an item silently undispositioned.

**2. `finding` tool** — `packages/core/src/tool/plugin/security/finding.ts` (+ `finding.txt`), also whole-list-replace. Each item has `id`, `title`, `class`, `status: "hypothesis" | "confirmed" | "blocked"`, `evidence` (prose), and two structured fields needed for replay without an LLM: `repro` (method/url/headers/body) and `expected` (status / bodyContains / bodyExcludes / minMillis — at least one must be set). `execute()` hand-validates (same pattern as `http.ts` lines 69–85) that `repro` and `expected` are both present whenever `status === "confirmed"`.

**3. The gate** — new `packages/core/src/session/runner/completion-gate.ts`, called from the `Completed` arm in `llm.ts` exactly where `!outcome.needsContinuation` would let the session go idle:
   - Reads the latest completed `coverage`/`finding` tool-call `metadata` by scanning `store.context(sessionID)` backwards (same message-walking pattern `settleStaleToolCalls` already uses in `llm.ts`) — no new DB read, no new table.
   - For items with `disposition === "untested"`, and for every `status === "confirmed"` finding, **deterministically replays** the finding's `repro` via `HttpClient.HttpClient` (reusing `http.ts`'s request-building and `collectBoundedResponseBody`) and checks the response against `expected`.
   - If anything is unresolved, returns `true` in place of `needsContinuation` — the *same* continuation mechanism already used when the model calls a tool — and publishes a `SessionEvent.Synthetic` message listing exactly what's unresolved and which tool to call to fix it (mirrors the voice of the existing `CONTINUE_AFTER_*` text).
   - A per-session in-memory rejection counter (plain `Map`, same scope/lifetime as the existing `titles` FiberMap in `llm.ts`) caps forced continuations at `GATE_MAX_REJECTIONS = 3`; past the cap, the session is allowed to go idle with a final synthetic warning listing what's still unresolved instead of looping forever.
   - "Tool never called" (no coverage/finding data at all) passes the gate — the gate only engages once the model has opted into using these tools. Both tools and gate enforcement ride on one shared `experimental` config flag (name: `security_gate`), matching `todo`'s one-flag precedent; no separate kill switch.
   - `HttpClient.HttpClient` needs to be added to `SessionRunnerLLM`'s layer deps in `llm.ts` (it's already a platform service used elsewhere in Core — mechanical, not a new concept).

No changes to `step.ts`, `publish-llm-event.ts`, `max-steps.ts`, or `sql.ts`; no migration.

## Files

**Add:**
- `packages/core/src/tool/plugin/security/coverage.ts`, `coverage.txt`
- `packages/core/src/tool/plugin/security/finding.ts`, `finding.txt`
- `packages/core/src/session/runner/completion-gate.ts`

**Modify:**
- `packages/core/src/session/runner/llm.ts` — import `CompletionGate`, thread `HttpClient.HttpClient` into the layer, add the rejection-count `Map`, extend the `Completed` arm.
- `packages/core/src/plugin/internal.ts` — register `CoverageTool.Plugin` / `FindingTool.Plugin` alongside `TodoTool.Plugin`.
- `packages/schema/src/config/experimental.ts` — new `security_gate` boolean flag.
- `packages/core/src/config/normalize.ts` — matching decode block.

## Deliberate scope choices (accepted, not re-litigating during implementation)

- Loop-safety counter is in-memory only, not durable — a process restart mid-gate just resets it to 0, giving a few extra forced-continuation rounds at worst, never a false "done." Not worth a migration/keyed-table for.
- Replay reuses `http.ts`'s existing concurrency(4)/timeout(30s)/size-cap(10MB) constants rather than deriving new ones.
- Replay is purely mechanical (send exactly what's recorded, check exactly what's expected) — it does not cross-reference a finding's URL against the live coverage ledger.
- "Never called the tools" passes the gate rather than blocking; this is opt-in instrumentation, not a mandatory checklist for every session.

## Verification

1. `bun typecheck` from `packages/core` after adding the two tools and the gate.
2. `bun run check` from repo root.
3. Manual smoke test via `bun run dev` against a local test target (e.g. the existing OWASP Juice Shop setup used earlier): drive a session that calls `coverage` with one `"untested"` item and `finding` with one `"confirmed"` item whose `repro`/`expected` don't actually hold, confirm the session is forced to continue with the synthetic message naming both, then resolve them and confirm it's allowed to go idle. Separately confirm `GATE_MAX_REJECTIONS` eventually lets it idle with a warning if left unresolved.
4. Confirm a session that never calls `coverage`/`finding` completes exactly as it does today (no behavior change when the tools aren't used).

## Status

Not yet implemented — this is the design only, written up for reference. Implementation paused to investigate a live failure (NoSQL Exfiltration challenge) first.
