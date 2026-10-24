export * as NaabuTool from "./naabu.js"

import type { Context } from "@opencode/plugin/effect/plugin"
import { Effect, Schema } from "effect"
import { AppProcess } from "@opencode/util/process"
import { Permission } from "../../../permission.js"
import { SecurityExec } from "./exec.js"

export const name = "naabu"
const EXECUTABLES = ["naabu"]
const DOCS_URL = "https://github.com/projectdiscovery/naabu"

export const Input = Schema.Struct({
  target: Schema.String.annotate({ description: "Host, IP address, or hostname to port-scan." }),
  ports: Schema.optionalKey(Schema.String).annotate({
    description: 'Ports or port ranges to scan, e.g. "80,443" or "1-1000". Defaults to naabu\'s top 100 ports.',
  }),
})

export const Output = SecurityExec.Output

export const Plugin = {
  id: "opencode.tool.security.naabu",
  effect: Effect.fn("NaabuTool.Plugin")(function* (ctx: Context) {
    const proc = yield* AppProcess.Service
    const permission = yield* Permission.Service

    yield* ctx.tool
      .transform((editor) =>
        editor.add({
          name,
          options: { codemode: false },
          description: "Fast port scan of a host with naabu. Lighter and quicker than nmap for simple host discovery.",
          input: Input,
          output: Output,
          execute: (input, context) => {
            const bin = SecurityExec.resolveExecutable(EXECUTABLES)
            if (!bin) return Effect.fail(SecurityExec.missingExecutableFailure(name, EXECUTABLES, DOCS_URL))
            const args = ["-host", input.target, ...(input.ports ? ["-p", input.ports] : [])]
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
