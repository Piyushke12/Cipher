export * as HttpxTool from "./httpx.js"

import type { Context } from "@opencode/plugin/effect/plugin"
import { Effect, Schema } from "effect"
import { AppProcess } from "@opencode/util/process"
import { Permission } from "../../../permission.js"
import { SecurityExec } from "./exec.js"

export const name = "httpx"
const EXECUTABLES = ["httpx"]
const DOCS_URL = "https://github.com/projectdiscovery/httpx"

export const Input = Schema.Struct({
  url: Schema.String.annotate({ description: "URL or host to probe." }),
  path: Schema.optionalKey(Schema.String).annotate({ description: "Optional path to probe, e.g. /api/health." }),
})

export const Output = SecurityExec.Output

export const Plugin = {
  id: "opencode.tool.security.httpx",
  effect: Effect.fn("HttpxTool.Plugin")(function* (ctx: Context) {
    const proc = yield* AppProcess.Service
    const permission = yield* Permission.Service

    yield* ctx.tool
      .transform((editor) =>
        editor.add({
          name,
          options: { codemode: false },
          description:
            "Probe an HTTP(S) target with httpx: status code, title, and technology detection, following redirects. Faster and more structured than webfetch for recon.",
          input: Input,
          output: Output,
          execute: (input, context) => {
            const bin = SecurityExec.resolveExecutable(EXECUTABLES)
            if (!bin) return Effect.fail(SecurityExec.missingExecutableFailure(name, EXECUTABLES, DOCS_URL))
            const args = [
              "-u",
              SecurityExec.normalizeLocalhost(input.url),
              "-json",
              "-silent",
              "-follow-redirects",
              "-title",
              "-tech-detect",
              ...(input.path ? ["-path", input.path] : []),
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
