export * as ZapTool from "./zap.js"

import type { Context } from "@opencode/plugin/effect/plugin"
import { Effect, Schema } from "effect"
import { AppProcess } from "@opencode/util/process"
import { Permission } from "../../../permission.js"
import { SecurityExec } from "./exec.js"

export const name = "zap"
const EXECUTABLES = ["zap", "zaproxy", "owasp-zap"]
const DOCS_URL = "https://www.zaproxy.org"

export const Input = Schema.Struct({
  url: Schema.String.annotate({ description: "Target URL for a ZAP quick baseline scan." }),
})

export const Output = SecurityExec.Output

export const Plugin = {
  id: "opencode.tool.security.zap",
  effect: Effect.fn("ZapTool.Plugin")(function* (ctx: Context) {
    const proc = yield* AppProcess.Service
    const permission = yield* Permission.Service

    yield* ctx.tool
      .transform((editor) =>
        editor.add({
          name,
          options: { codemode: false },
          description: "Run an OWASP ZAP headless quick baseline dynamic scan against a URL. Requires Java.",
          input: Input,
          output: Output,
          execute: (input, context) => {
            const bin = SecurityExec.resolveExecutable(EXECUTABLES)
            if (!bin) return Effect.fail(SecurityExec.missingExecutableFailure(name, EXECUTABLES, DOCS_URL))
            // -cmd forces headless mode; bare zap opens a GUI and hangs.
            const args = ["-cmd", "-quickurl", input.url, "-quickprogress"]
            return SecurityExec.runTool({
              proc,
              permission,
              name,
              resource: input.url,
              bin,
              args,
              metadata: input,
              context,
              timeoutMs: 10 * 60 * 1_000,
            }).pipe(Effect.mapError(SecurityExec.toToolFailure(name)))
          },
        }),
      )
      .pipe(Effect.orDie)
  }),
}
