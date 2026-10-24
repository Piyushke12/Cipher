export * as AsnmapTool from "./asnmap.js"

import type { Context } from "@opencode/plugin/effect/plugin"
import { Effect, Schema } from "effect"
import { AppProcess } from "@opencode/util/process"
import { Permission } from "../../../permission.js"
import { SecurityExec } from "./exec.js"

export const name = "asnmap"
const EXECUTABLES = ["asnmap"]
const DOCS_URL = "https://github.com/projectdiscovery/asnmap"

export const Input = Schema.Struct({
  domain: Schema.String.annotate({ description: "Domain, IP, or ASN to map to its organization's IP ranges." }),
})

export const Output = SecurityExec.Output

export const Plugin = {
  id: "opencode.tool.security.asnmap",
  effect: Effect.fn("AsnmapTool.Plugin")(function* (ctx: Context) {
    const proc = yield* AppProcess.Service
    const permission = yield* Permission.Service

    yield* ctx.tool
      .transform((editor) =>
        editor.add({
          name,
          options: { codemode: false },
          description: "Map a domain/IP/ASN to its organization's IP ranges with asnmap. Useful for scoping external attack surface.",
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
