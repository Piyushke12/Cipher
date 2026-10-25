export * as NucleiTool from "./nuclei.js"

import type { Context } from "@opencode/plugin/effect/plugin"
import { Effect, Schema } from "effect"
import { AppProcess } from "@opencode/util/process"
import { Permission } from "../../../permission.js"
import { SecurityExec } from "./exec.js"

export const name = "nuclei"
const EXECUTABLES = ["nuclei"]
const DOCS_URL = "https://github.com/projectdiscovery/nuclei"

// A full, unscoped template run routinely exceeds SecurityExec.DEFAULT_TIMEOUT_MS (3 minutes);
// give nuclei specifically more room rather than timing out mid-scan.
const TIMEOUT_MS = 10 * 60 * 1_000

export const Input = Schema.Struct({
  target: Schema.String.annotate({ description: "URL or host to scan with nuclei's vulnerability templates." }),
  severity: Schema.optionalKey(Schema.Literals(["info", "low", "medium", "high", "critical"])).annotate({
    description: "Only run templates at or matching this severity. Prefer setting this (or tags) for a fast iterative check.",
  }),
  tags: Schema.optionalKey(Schema.String).annotate({
    description:
      "Comma-separated template tags to narrow the scan (e.g. \"cve,rce\" or \"exposed-panels\"). Prefer setting this (or severity) for a fast iterative check; an unscoped call (both omitted) is for one thorough final sweep, not repeated quick looks.",
  }),
  oast: Schema.optionalKey(Schema.Boolean).annotate({
    description:
      "Include OAST/interactsh (out-of-band) templates. These poll an external callback server and cannot work against a target that isn't reachable from the internet (e.g. localhost/an internal host) - they just sit waiting for a callback that will never arrive, which is usually why a scan appears to hang near the end. Defaults to false (excluded) for exactly that reason; set true only against a target the interactsh server can actually reach.",
  }),
})

export const Output = SecurityExec.Output

export const Plugin = {
  id: "opencode.tool.security.nuclei",
  effect: Effect.fn("NucleiTool.Plugin")(function* (ctx: Context) {
    const proc = yield* AppProcess.Service
    const permission = yield* Permission.Service

    yield* ctx.tool
      .transform((editor) =>
        editor.add({
          name,
          options: { codemode: false },
          description:
            "Run template-based vulnerability scanning against a target with nuclei. An unscoped run uses nuclei's full template set (7000+ templates) and routinely takes several minutes, even against one fast local target. For iterative work, scope with `tags` and/or `severity` for a fast signal; reserve an unscoped call (omit both) for a final, thorough sweep near the end of the assessment, not every time you want a quick check.",
          input: Input,
          output: Output,
          execute: (input, context) => {
            const bin = SecurityExec.resolveExecutable(EXECUTABLES)
            if (!bin) return Effect.fail(SecurityExec.missingExecutableFailure(name, EXECUTABLES, DOCS_URL))
            const args = [
              "-target",
              SecurityExec.normalizeLocalhost(input.target),
              "-jsonl",
              "-silent",
              ...(input.severity ? ["-severity", input.severity] : []),
              ...(input.tags ? ["-tags", input.tags] : []),
              ...(input.oast ? [] : ["-ni"]),
            ]
            return SecurityExec.runTool({
              proc,
              permission,
              name,
              resource: input.target,
              bin,
              args,
              timeoutMs: TIMEOUT_MS,
              metadata: input,
              context,
            }).pipe(Effect.mapError(SecurityExec.toToolFailure(name)))
          },
        }),
      )
      .pipe(Effect.orDie)
  }),
}
