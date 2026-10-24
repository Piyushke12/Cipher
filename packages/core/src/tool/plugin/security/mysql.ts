export * as MysqlTool from "./mysql.js"

import type { Context } from "@opencode/plugin/effect/plugin"
import { Effect, Schema } from "effect"
import { AppProcess } from "@opencode/util/process"
import { Permission } from "../../../permission.js"
import { SecurityExec } from "./exec.js"

export const name = "mysql"
const EXECUTABLES = ["mysql"]
const DOCS_URL = "https://dev.mysql.com/downloads/mysql/"

const AUDIT_QUERY =
  "SELECT VERSION() AS version; SHOW VARIABLES WHERE Variable_name IN ('sql_mode','skip_networking','bind_address','general_log','require_secure_transport','have_ssl','log_output'); SELECT user,host,plugin,authentication_string='' AS empty_password FROM mysql.user; SHOW GRANTS;"

export const Input = Schema.Struct({
  host: Schema.String.annotate({ description: "MySQL/MariaDB server host to audit." }),
  username: Schema.optionalKey(Schema.String).annotate({ description: "Username to connect with." }),
  password: Schema.optionalKey(Schema.String).annotate({ description: "Password to connect with." }),
})

export const Output = SecurityExec.Output

export const Plugin = {
  id: "opencode.tool.security.mysql",
  effect: Effect.fn("MysqlTool.Plugin")(function* (ctx: Context) {
    const proc = yield* AppProcess.Service
    const permission = yield* Permission.Service

    yield* ctx.tool
      .transform((editor) =>
        editor.add({
          name,
          options: { codemode: false },
          description:
            "Audit a MySQL/MariaDB server's configuration and authentication posture: version, TLS/logging settings, users, empty-password accounts, and grants. A missing password fails fast instead of prompting.",
          input: Input,
          output: Output,
          execute: (input, context) => {
            const bin = SecurityExec.resolveExecutable(EXECUTABLES)
            if (!bin) return Effect.fail(SecurityExec.missingExecutableFailure(name, EXECUTABLES, DOCS_URL))
            const args = [
              "--host",
              input.host,
              "--batch",
              "--execute",
              AUDIT_QUERY,
              ...(input.username ? ["--user", input.username] : []),
              ...(input.password ? [`--password${input.password}`] : []),
            ]
            return SecurityExec.runTool({
              proc,
              permission,
              name,
              resource: input.host,
              bin,
              args,
              metadata: { host: input.host, username: input.username },
              context,
            }).pipe(Effect.mapError(SecurityExec.toToolFailure(name)))
          },
        }),
      )
      .pipe(Effect.orDie)
  }),
}
