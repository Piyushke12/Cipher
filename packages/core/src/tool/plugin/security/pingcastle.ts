export * as PingcastleTool from "./pingcastle.js"

import type { Context } from "@opencode/plugin/effect/plugin"
import { Effect, Schema } from "effect"
import { AppProcess } from "@opencode/util/process"
import { Permission } from "../../../permission.js"
import { SecurityExec } from "./exec.js"

export const name = "pingcastle"
const EXECUTABLES = ["pingcastle", "PingCastle"]
const DOCS_URL = "https://www.pingcastle.com"

export const Input = Schema.Struct({
  server: Schema.String.annotate({ description: "Domain or domain controller hostname to assess over LDAP." }),
})

export const Output = SecurityExec.Output

export const Plugin = {
  id: "opencode.tool.security.pingcastle",
  effect: Effect.fn("PingcastleTool.Plugin")(function* (ctx: Context) {
    const proc = yield* AppProcess.Service
    const permission = yield* Permission.Service

    yield* ctx.tool
      .transform((editor) =>
        editor.add({
          name,
          options: { codemode: false },
          description:
            "Run a PingCastle Active Directory security healthcheck (users, privileges, trusts, attack paths) against a domain or domain controller. Windows only.",
          input: Input,
          output: Output,
          execute: (input, context) => {
            const bin = SecurityExec.resolveExecutable(EXECUTABLES)
            if (!bin) return Effect.fail(SecurityExec.missingExecutableFailure(name, EXECUTABLES, DOCS_URL))
            const args = ["--healthcheck", "--server", input.server]
            return SecurityExec.runTool({
              proc,
              permission,
              name,
              resource: input.server,
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
