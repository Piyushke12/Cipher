export * as SyftTool from "./syft.js"

import type { Context } from "@opencode/plugin/effect/plugin"
import { Effect, Schema } from "effect"
import { AppProcess } from "@opencode/util/process"
import { FileAccess } from "../../../file-access.js"
import { Permission } from "../../../permission.js"
import { RelativePath } from "../../../schema.js"
import { SecurityExec } from "./exec.js"

export const name = "syft"
const EXECUTABLES = ["syft"]
const DOCS_URL = "https://github.com/anchore/syft"

export const Input = Schema.Struct({
  path: Schema.optionalKey(RelativePath).annotate({
    description: "Filesystem path to generate a software bill of materials (SBOM) for. Defaults to the current working directory.",
  }),
})

export const Output = SecurityExec.Output

export const Plugin = {
  id: "opencode.tool.security.syft",
  effect: Effect.fn("SyftTool.Plugin")(function* (ctx: Context) {
    const proc = yield* AppProcess.Service
    const permission = yield* Permission.Service
    const access = yield* FileAccess.Service

    yield* ctx.tool
      .transform((editor) =>
        editor.add({
          name,
          options: { codemode: false },
          description: "Generate a software bill of materials (SBOM) for a filesystem path with syft.",
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
                args: [target.absolute, "-o", "json"],
                metadata: input,
                context,
              })
            }).pipe(Effect.mapError(SecurityExec.toToolFailure(name))),
        }),
      )
      .pipe(Effect.orDie)
  }),
}
