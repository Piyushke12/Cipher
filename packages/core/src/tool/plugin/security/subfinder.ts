export * as SubfinderTool from "./subfinder.js"

import type { Context } from "@opencode/plugin/effect/plugin"
import { Effect, Schema } from "effect"
import { AppProcess } from "@opencode/util/process"
import { Permission } from "../../../permission.js"
import { SecurityExec } from "./exec.js"

export const name = "subfinder"
const EXECUTABLES = ["subfinder"]
const DOCS_URL = "https://github.com/projectdiscovery/subfinder"

export const Input = Schema.Struct({
  domain: Schema.String.annotate({ description: "Root domain to enumerate subdomains for, e.g. example.com." }),
})

export const Output = SecurityExec.Output

export const Plugin = {
  id: "opencode.tool.security.subfinder",
  effect: Effect.fn("SubfinderTool.Plugin")(function* (ctx: Context) {
    const proc = yield* AppProcess.Service
    const permission = yield* Permission.Service

    yield* ctx.tool
      .transform((editor) =>
        editor.add({
          name,
          options: { codemode: false },
          description: "Passively enumerate subdomains of a domain with subfinder.",
          input: Input,
          output: Output,
          execute: (input, context) => {
            const bin = SecurityExec.resolveExecutable(EXECUTABLES)
            if (!bin) return Effect.fail(SecurityExec.missingExecutableFailure(name, EXECUTABLES, DOCS_URL))
            const args = ["-d", input.domain]
            return SecurityExec.runTool({
              proc,
              permission,
              name,
              resource: input.domain,
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
