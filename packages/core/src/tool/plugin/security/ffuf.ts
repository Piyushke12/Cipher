export * as FfufTool from "./ffuf.js"

import type { Context } from "@opencode/plugin/effect/plugin"
import { Effect, Schema } from "effect"
import { fileURLToPath } from "node:url"
import { AppProcess } from "@opencode/util/process"
import { Permission } from "../../../permission.js"
import { SecurityExec } from "./exec.js"

export const name = "ffuf"
const EXECUTABLES = ["ffuf"]
const DOCS_URL = "https://github.com/ffuf/ffuf"
// Small bundled sample wordlist, not a production fuzzing list — pass `wordlist` for real coverage.
const DEFAULT_WORDLIST = fileURLToPath(new URL("./wordlists/common.txt", import.meta.url))

export const Input = Schema.Struct({
  url: Schema.String.annotate({ description: 'Base URL to fuzz. The literal "FUZZ" is appended as the path to fuzz.' }),
  wordlist: Schema.optionalKey(Schema.String).annotate({
    description: "Absolute path to a wordlist. Defaults to a small bundled sample list.",
  }),
})

export const Output = SecurityExec.Output

export const Plugin = {
  id: "opencode.tool.security.ffuf",
  effect: Effect.fn("FfufTool.Plugin")(function* (ctx: Context) {
    const proc = yield* AppProcess.Service
    const permission = yield* Permission.Service

    yield* ctx.tool
      .transform((editor) =>
        editor.add({
          name,
          options: { codemode: false },
          description:
            "Fuzz a web application for hidden endpoints and parameters with ffuf. Auto-calibrates against baseline responses to filter SPA fallback noise.",
          input: Input,
          output: Output,
          execute: (input, context) => {
            const bin = SecurityExec.resolveExecutable(EXECUTABLES)
            if (!bin) return Effect.fail(SecurityExec.missingExecutableFailure(name, EXECUTABLES, DOCS_URL))
            const args = ["-u", `${input.url}/FUZZ`, "-w", input.wordlist ?? DEFAULT_WORDLIST, "-ac", "-s"]
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
