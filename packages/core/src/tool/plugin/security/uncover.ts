export * as UncoverTool from "./uncover.js"

import type { Context } from "@opencode/plugin/effect/plugin"
import { Effect, Schema } from "effect"
import { AppProcess } from "@opencode/util/process"
import { Permission } from "../../../permission.js"
import { SecurityExec } from "./exec.js"

export const name = "uncover"
const EXECUTABLES = ["uncover"]
const DOCS_URL = "https://github.com/projectdiscovery/uncover"

export const Input = Schema.Struct({
  query: Schema.String.annotate({
    description:
      'Search-engine query for exposed hosts, e.g. "domain:example.com" or "domain:example.com AND port:3306". Requires Shodan/Censys/FOFA API keys configured for uncover.',
  }),
})

export const Output = SecurityExec.Output

export const Plugin = {
  id: "opencode.tool.security.uncover",
  effect: Effect.fn("UncoverTool.Plugin")(function* (ctx: Context) {
    const proc = yield* AppProcess.Service
    const permission = yield* Permission.Service

    yield* ctx.tool
      .transform((editor) =>
        editor.add({
          name,
          options: { codemode: false },
          description:
            "Discover internet-exposed hosts via search engines (Shodan/Censys/FOFA-style) with uncover. Useful for finding exposed services, including databases, without touching the target directly.",
          input: Input,
          output: Output,
          execute: (input, context) => {
            const bin = SecurityExec.resolveExecutable(EXECUTABLES)
            if (!bin) return Effect.fail(SecurityExec.missingExecutableFailure(name, EXECUTABLES, DOCS_URL))
            const args = ["-q", input.query]
            return SecurityExec.runTool({
              proc,
              permission,
              name,
              resource: input.query,
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
