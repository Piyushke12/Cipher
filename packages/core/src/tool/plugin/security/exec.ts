export * as SecurityExec from "./exec.js"

import { ToolFailure } from "@opencode/ai"
import { Effect, Schema } from "effect"
import { ChildProcess } from "effect/process"
import { AppProcess } from "@opencode/util/process"
import type { Tool } from "@opencode/schema/tool"
import { Permission } from "../../../permission.js"
import { which } from "../../../util/which.js"

export const DEFAULT_TIMEOUT_MS = 3 * 60 * 1_000
const MAX_OUTPUT_BYTES = 500_000

export const Output = Schema.Struct({
  exitCode: Schema.Number,
  output: Schema.String,
  truncated: Schema.Boolean,
})

/**
 * projectdiscovery's tools (httpx, katana, nuclei, ffuf's DNS-less path works fine, but the
 * shared resolver underneath httpx/katana/nuclei) resolve the literal hostname "localhost"
 * unreliably on this host - httpx fails outright, katana only intermittently. Rewrite a bare
 * "localhost" host component to "127.0.0.1", which both resolves correctly and is what a user
 * means by "localhost" in practice.
 */
export function normalizeLocalhost(value: string) {
  return value.replace(/^(https?:\/\/)?localhost(?=[:/]|$)/i, "$1127.0.0.1")
}

/** First PATH match from a list of candidate executable names, or undefined. */
export function resolveExecutable(candidates: readonly string[]) {
  for (const candidate of candidates) {
    const found = which(candidate)
    if (found) return found
  }
  return undefined
}

export function missingExecutableFailure(name: string, candidates: readonly string[], docsUrl: string) {
  return new ToolFailure({
    message: `${name} is not installed or not on PATH (looked for: ${candidates.join(", ")}). Install it from ${docsUrl}, then retry.`,
  })
}

/** Run an already-resolved security CLI binary with a fixed argv and report its combined output. */
export const runTool = Effect.fn("SecurityExec.runTool")(function* (input: {
  readonly proc: AppProcess.Interface
  readonly permission: Permission.Interface
  readonly name: string
  readonly resource: string
  readonly bin: string
  readonly args: readonly string[]
  readonly cwd?: string
  readonly timeoutMs?: number
  readonly metadata: Record<string, unknown>
  readonly context: Tool.Context
}) {
  yield* input.permission.assert({
    action: input.name,
    resources: [input.resource],
    save: ["*"],
    metadata: input.metadata,
    sessionID: input.context.sessionID,
    agent: input.context.agent,
    source: { type: "tool" as const, messageID: input.context.messageID, id: input.context.id },
  })
  const result = yield* input.proc.run(
    ChildProcess.make(input.bin, [...input.args], { cwd: input.cwd, extendEnv: true, stdin: "ignore" }),
    { timeout: input.timeoutMs ?? DEFAULT_TIMEOUT_MS, maxOutputBytes: MAX_OUTPUT_BYTES, maxErrorBytes: MAX_OUTPUT_BYTES },
  )
  const stdout = result.stdout.toString("utf8").trim()
  const stderr = result.stderr.toString("utf8").trim()
  const output = [stdout, stderr && `[stderr]\n${stderr}`].filter((part) => !!part).join("\n\n")
  return {
    output: {
      exitCode: result.exitCode,
      output,
      truncated: result.stdoutTruncated || result.stderrTruncated,
    },
    content: output || `(${input.name} exited ${result.exitCode} with no output)`,
    metadata: { exitCode: result.exitCode },
  }
})

/** Shared outer error boundary: wrap any surviving typed failure as a ToolFailure. */
export function toToolFailure(name: string) {
  return (error: unknown) => (error instanceof ToolFailure ? error : new ToolFailure({ message: `Unable to run ${name}`, error }))
}
