export * as TlsxTool from "./tlsx.js"

import type { Context } from "@opencode/plugin/effect/plugin"
import { Effect, Schema } from "effect"
import { AppProcess } from "@opencode/util/process"
import { Permission } from "../../../permission.js"
import { SecurityExec } from "./exec.js"

export const name = "tlsx"
const EXECUTABLES = ["tlsx"]
const DOCS_URL = "https://github.com/projectdiscovery/tlsx"

export const Input = Schema.Struct({
  host: Schema.String.annotate({ description: "Host or host:port to probe for TLS certificate and configuration." }),
})

export const Output = SecurityExec.Output

export const Plugin = {
  id: "opencode.tool.security.tlsx",
  effect: Effect.fn("TlsxTool.Plugin")(function* (ctx: Context) {
    const proc = yield* AppProcess.Service
    const permission = yield* Permission.Service

    yield* ctx.tool
      .transform((editor) =>
        editor.add({
          name,
          options: { codemode: false },
          description: "Probe TLS certificate and configuration of a host with tlsx.",
          input: Input,
          output: Output,
          execute: (input, context) => {
            const bin = SecurityExec.resolveExecutable(EXECUTABLES)
            if (!bin) return Effect.fail(SecurityExec.missingExecutableFailure(name, EXECUTABLES, DOCS_URL))
            const args = ["-host", input.host, "-json"]
            return SecurityExec.runTool({
              proc,
              permission,
              name,
              resource: input.host,
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
