export * as InteractshTool from "./interactsh.js"

import type { Context } from "@opencode/plugin/effect/plugin"
import { Effect, Schema } from "effect"
import { fileURLToPath } from "node:url"
import { AppProcess } from "@opencode/util/process"
import { Permission } from "../../../permission.js"
import { SecurityExec } from "./exec.js"

export const name = "interactsh"
const EXECUTABLES = ["node"]
const DOCS_URL = "https://github.com/projectdiscovery/interactsh"
const SCRIPT = fileURLToPath(new URL("./scripts/medusa-oob.mjs", import.meta.url))

export const Input = Schema.Struct({
  target: Schema.optionalKey(Schema.String).annotate({ description: "Target this listener is being used against, for your own tracking." }),
  action: Schema.Literals(["start", "check", "stop"])
    .annotate({
      description:
        "start: register a listener and get a callback URL to embed in payloads (blind SSRF/XXE/injection). check: report collected callbacks. stop: tear down the listener.",
    })
    .pipe(Schema.withDecodingDefaultKey(Effect.succeed("check" as const))),
})

export const Output = SecurityExec.Output

export const Plugin = {
  id: "opencode.tool.security.interactsh",
  effect: Effect.fn("InteractshTool.Plugin")(function* (ctx: Context) {
    const proc = yield* AppProcess.Service
    const permission = yield* Permission.Service

    yield* ctx.tool
      .transform((editor) =>
        editor.add({
          name,
          options: { codemode: false },
          description:
            "Out-of-band (OOB) interaction testing for blind SSRF/XXE/injection via interactsh. Start a listener to get a callback URL, embed it in a payload, deliver it, then check for callbacks. Requires Node and interactsh-client on PATH.",
          input: Input,
          output: Output,
          execute: (input, context) => {
            const bin = SecurityExec.resolveExecutable(EXECUTABLES)
            if (!bin) return Effect.fail(SecurityExec.missingExecutableFailure(name, EXECUTABLES, DOCS_URL))
            const args = [SCRIPT, "--action", input.action, ...(input.target ? ["--target", input.target] : [])]
            return SecurityExec.runTool({
              proc,
              permission,
              name,
              resource: input.target ?? input.action,
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
