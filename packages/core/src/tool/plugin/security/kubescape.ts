export * as KubescapeTool from "./kubescape.js"

import type { Context } from "@opencode/plugin/effect/plugin"
import { Effect, Schema } from "effect"
import { AppProcess } from "@opencode/util/process"
import { Permission } from "../../../permission.js"
import { SecurityExec } from "./exec.js"

export const name = "kubescape"
const EXECUTABLES = ["kubescape"]
const DOCS_URL = "https://github.com/kubescape/kubescape"

export const Input = Schema.Struct({
  target: Schema.String.annotate({
    description: "Kubernetes manifest file, directory, repo URL, or cluster reference to scan.",
  }),
})

export const Output = SecurityExec.Output

export const Plugin = {
  id: "opencode.tool.security.kubescape",
  effect: Effect.fn("KubescapeTool.Plugin")(function* (ctx: Context) {
    const proc = yield* AppProcess.Service
    const permission = yield* Permission.Service

    yield* ctx.tool
      .transform((editor) =>
        editor.add({
          name,
          options: { codemode: false },
          description: "Scan Kubernetes manifests or a live cluster for security posture issues with kubescape.",
          input: Input,
          output: Output,
          execute: (input, context) => {
            const bin = SecurityExec.resolveExecutable(EXECUTABLES)
            if (!bin) return Effect.fail(SecurityExec.missingExecutableFailure(name, EXECUTABLES, DOCS_URL))
            const args = ["scan", "framework", "all", "--format", "json", input.target]
            return SecurityExec.runTool({
              proc,
              permission,
              name,
              resource: input.target,
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
