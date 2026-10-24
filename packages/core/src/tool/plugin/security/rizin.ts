export * as RizinTool from "./rizin.js"

import type { Context } from "@opencode/plugin/effect/plugin"
import { Effect, Schema } from "effect"
import { AppProcess } from "@opencode/util/process"
import { FileAccess } from "../../../file-access.js"
import { Permission } from "../../../permission.js"
import { RelativePath } from "../../../schema.js"
import { SecurityExec } from "./exec.js"

export const name = "rizin"
const EXECUTABLES = ["rizin", "radare2", "r2"]
const DOCS_URL = "https://rizin.re"

export const Input = Schema.Struct({
  path: RelativePath.annotate({ description: "Binary file to analyze." }),
})

export const Output = SecurityExec.Output

export const Plugin = {
  id: "opencode.tool.security.rizin",
  effect: Effect.fn("RizinTool.Plugin")(function* (ctx: Context) {
    const proc = yield* AppProcess.Service
    const permission = yield* Permission.Service
    const access = yield* FileAccess.Service

    yield* ctx.tool
      .transform((editor) =>
        editor.add({
          name,
          options: { codemode: false },
          description: "Run a batch analysis pass (aaa) and print binary info with rizin (radare2 family).",
          input: Input,
          output: Output,
          execute: (input, context) =>
            Effect.gen(function* () {
              const bin = SecurityExec.resolveExecutable(EXECUTABLES)
              if (!bin) return yield* SecurityExec.missingExecutableFailure(name, EXECUTABLES, DOCS_URL)
              const target = yield* access.resolve({ path: input.path, kind: "file" })
              yield* access.authorizeExternal([target], context)
              return yield* SecurityExec.runTool({
                proc,
                permission,
                name,
                resource: target.absolute,
                bin,
                // -q -c runs a batch command and exits; bare rizin opens an interactive REPL.
                args: ["-q", "-c", "aaa;i", target.absolute],
                metadata: input,
                context,
              })
            }).pipe(Effect.mapError(SecurityExec.toToolFailure(name))),
        }),
      )
      .pipe(Effect.orDie)
  }),
}
