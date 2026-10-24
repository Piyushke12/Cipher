export * as GrypeTool from "./grype.js"

import type { Context } from "@opencode/plugin/effect/plugin"
import { Effect, Schema } from "effect"
import { AppProcess } from "@opencode/util/process"
import { FileAccess } from "../../../file-access.js"
import { Permission } from "../../../permission.js"
import { RelativePath } from "../../../schema.js"
import { SecurityExec } from "./exec.js"

export const name = "grype"
const EXECUTABLES = ["grype"]
const DOCS_URL = "https://github.com/anchore/grype"

export const Input = Schema.Struct({
  path: Schema.optionalKey(RelativePath).annotate({
    description: "Filesystem directory to scan for known vulnerabilities. Defaults to the current working directory.",
  }),
})

export const Output = SecurityExec.Output

export const Plugin = {
  id: "opencode.tool.security.grype",
  effect: Effect.fn("GrypeTool.Plugin")(function* (ctx: Context) {
    const proc = yield* AppProcess.Service
    const permission = yield* Permission.Service
    const access = yield* FileAccess.Service

    yield* ctx.tool
      .transform((editor) =>
        editor.add({
          name,
          options: { codemode: false },
          description:
            "Scan a filesystem directory for known vulnerabilities with grype. Treats the target as a local directory, never pulls a registry image.",
          input: Input,
          output: Output,
          execute: (input, context) =>
            Effect.gen(function* () {
              const bin = SecurityExec.resolveExecutable(EXECUTABLES)
              if (!bin) return yield* SecurityExec.missingExecutableFailure(name, EXECUTABLES, DOCS_URL)
              const target = yield* access.resolve({ path: input.path ?? "." })
              yield* access.authorizeExternal([target], context)
              return yield* SecurityExec.runTool({
                proc,
                permission,
                name,
                resource: target.absolute,
                bin,
                // NOTE: grype treats a bare value as a container image reference and tries a registry
                // pull. The `dir:` scheme forces local filesystem scanning.
                args: [`dir:${target.absolute}`, "-o", "json"],
                metadata: input,
                context,
              })
            }).pipe(Effect.mapError(SecurityExec.toToolFailure(name))),
        }),
      )
      .pipe(Effect.orDie)
  }),
}
