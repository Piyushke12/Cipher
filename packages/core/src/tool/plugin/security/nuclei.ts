export * as NucleiTool from "./nuclei.js"

import type { Context } from "@opencode/plugin/effect/plugin"
import { Effect, Schema } from "effect"
import { AppProcess } from "@opencode/util/process"
import { Permission } from "../../../permission.js"
import { SecurityExec } from "./exec.js"

export const name = "nuclei"
const EXECUTABLES = ["nuclei"]
const DOCS_URL = "https://github.com/projectdiscovery/nuclei"

export const Input = Schema.Struct({
  target: Schema.String.annotate({ description: "URL or host to scan with nuclei's vulnerability templates." }),
  severity: Schema.optionalKey(Schema.Literals(["info", "low", "medium", "high", "critical"])).annotate({
    description: "Only run templates at or matching this severity.",
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
          description: "Run template-based vulnerability scanning against a target with nuclei.",
          input: Input,
          output: Output,
          execute: (input, context) => {
            const bin = SecurityExec.resolveExecutable(EXECUTABLES)
            if (!bin) return Effect.fail(SecurityExec.missingExecutableFailure(name, EXECUTABLES, DOCS_URL))
            const args = [
              "-target",
              input.target,
              "-jsonl",
              "-silent",
              ...(input.severity ? ["-severity", input.severity] : []),
            ]
            return SecurityExec.runTool({
              proc,
              permission,
              name,
              resource: input.target,
              bin,
              args,
              metadata: input,
              context,
            }).pipe(Effect.mapError(SecurityExec.toToolFailure(name)))
          },
        }),
      )
      .pipe(Effect.orDie)
  }),
}
