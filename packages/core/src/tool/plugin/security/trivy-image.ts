export * as TrivyImageTool from "./trivy-image.js"

import type { Context } from "@opencode/plugin/effect/plugin"
import { Effect, Schema } from "effect"
import { AppProcess } from "@opencode/util/process"
import { Permission } from "../../../permission.js"
import { SecurityExec } from "./exec.js"

export const name = "trivy_image"
const EXECUTABLES = ["trivy"]
const DOCS_URL = "https://github.com/aquasecurity/trivy"

export const Input = Schema.Struct({
  image: Schema.String.annotate({
    description: 'Container image reference to scan, e.g. "nginx:latest" or "localhost:5000/app". Requires the Docker daemon or registry access.',
  }),
})

export const Output = SecurityExec.Output

export const Plugin = {
  id: "opencode.tool.security.trivy-image",
  effect: Effect.fn("TrivyImageTool.Plugin")(function* (ctx: Context) {
    const proc = yield* AppProcess.Service
    const permission = yield* Permission.Service

    yield* ctx.tool
      .transform((editor) =>
        editor.add({
          name,
          options: { codemode: false },
          description: "Scan a container image for vulnerabilities and misconfigurations with trivy.",
          input: Input,
          output: Output,
          execute: (input, context) => {
            const bin = SecurityExec.resolveExecutable(EXECUTABLES)
            if (!bin) return Effect.fail(SecurityExec.missingExecutableFailure(name, EXECUTABLES, DOCS_URL))
            const args = ["image", "--format", "json", input.image]
            return SecurityExec.runTool({
              proc,
              permission,
              name,
              resource: input.image,
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
