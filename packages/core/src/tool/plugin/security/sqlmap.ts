export * as SqlmapTool from "./sqlmap.js"

import type { Context } from "@opencode/plugin/effect/plugin"
import { Effect, Schema } from "effect"
import { AppProcess } from "@opencode/util/process"
import { Permission } from "../../../permission.js"
import { SecurityExec } from "./exec.js"

export const name = "sqlmap"
const EXECUTABLES = ["sqlmap", "sqlmap.py"]
const DOCS_URL = "https://sqlmap.org"

export const Input = Schema.Struct({
  url: Schema.String.annotate({
    description: "Full target endpoint URL including path and query string, e.g. https://example.com/item?id=1.",
  }),
  method: Schema.optionalKey(Schema.String).annotate({ description: "HTTP method, e.g. POST. Defaults to GET." }),
  data: Schema.optionalKey(Schema.String).annotate({ description: "POST body data to send with the request." }),
  parameter: Schema.optionalKey(Schema.String).annotate({ description: "Specific parameter name to test." }),
})

export const Output = SecurityExec.Output

export const Plugin = {
  id: "opencode.tool.security.sqlmap",
  effect: Effect.fn("SqlmapTool.Plugin")(function* (ctx: Context) {
    const proc = yield* AppProcess.Service
    const permission = yield* Permission.Service

    yield* ctx.tool
      .transform((editor) =>
        editor.add({
          name,
          options: { codemode: false },
          description: "Automatically test a URL/parameter for SQL injection with sqlmap. The target must be a full endpoint URL, not a bare origin.",
          input: Input,
          output: Output,
          execute: (input, context) => {
            const bin = SecurityExec.resolveExecutable(EXECUTABLES)
            if (!bin) return Effect.fail(SecurityExec.missingExecutableFailure(name, EXECUTABLES, DOCS_URL))
            const args = [
              "-u",
              input.url,
              "--batch",
              "--non-interactive",
              ...(input.method ? ["--method", input.method] : []),
              ...(input.data ? ["--data", input.data] : []),
              ...(input.parameter ? ["-p", input.parameter] : []),
            ]
            return SecurityExec.runTool({
              proc,
              permission,
              name,
              resource: input.url,
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
