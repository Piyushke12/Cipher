export * as PsqlTool from "./psql.js"

import type { Context } from "@opencode/plugin/effect/plugin"
import { Effect, Schema } from "effect"
import { AppProcess } from "@opencode/util/process"
import { Permission } from "../../../permission.js"
import { SecurityExec } from "./exec.js"

export const name = "psql"
const EXECUTABLES = ["psql"]
const DOCS_URL = "https://www.postgresql.org/download/"

const AUDIT_QUERY =
  "SELECT version(); SELECT name,setting FROM pg_settings WHERE name IN ('ssl','password_encryption','log_connections','log_disconnections','listen_addresses','row_security'); SELECT rolname,rolsuper,rolcreaterole,rolcreatedb,rolcanlogin FROM pg_roles;"

export const Input = Schema.Struct({
  host: Schema.String.annotate({ description: "PostgreSQL server host to audit." }),
  username: Schema.optionalKey(Schema.String).annotate({ description: "Username to connect with." }),
})

export const Output = SecurityExec.Output

export const Plugin = {
  id: "opencode.tool.security.psql",
  effect: Effect.fn("PsqlTool.Plugin")(function* (ctx: Context) {
    const proc = yield* AppProcess.Service
    const permission = yield* Permission.Service

    yield* ctx.tool
      .transform((editor) =>
        editor.add({
          name,
          options: { codemode: false },
          description:
            "Audit a PostgreSQL server's configuration and role posture: version, TLS/logging settings, and role privileges. Password-auth servers need credentials in ~/.pgpass; this never prompts for a password.",
          input: Input,
          output: Output,
          execute: (input, context) => {
            const bin = SecurityExec.resolveExecutable(EXECUTABLES)
            if (!bin) return Effect.fail(SecurityExec.missingExecutableFailure(name, EXECUTABLES, DOCS_URL))
            const args = [
              "--host",
              input.host,
              "--no-psqlrc",
              "--no-password",
              "--no-align",
              "--command",
              AUDIT_QUERY,
              ...(input.username ? ["--username", input.username] : []),
            ]
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
