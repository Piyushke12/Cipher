export * as NmapTool from "./nmap.js"

import type { Context } from "@opencode/plugin/effect/plugin"
import { Effect, Schema } from "effect"
import { AppProcess } from "@opencode/util/process"
import { Permission } from "../../../permission.js"
import { SecurityExec } from "./exec.js"

export const name = "nmap"
const EXECUTABLES = ["nmap"]
const DOCS_URL = "https://nmap.org"

export const Input = Schema.Struct({
  target: Schema.String.annotate({ description: "Host, IP address, hostname, or CIDR range to scan." }),
  ports: Schema.optionalKey(Schema.String).annotate({
    description: 'Ports or port ranges to scan, e.g. "80,443" or "1-1000". Defaults to nmap\'s top 1000 ports.',
  }),
  osDetection: Schema.optionalKey(Schema.Boolean).annotate({
    description: "Enable OS fingerprinting (-O). Often requires elevated privileges.",
  }),
  bannerGrabbing: Schema.optionalKey(Schema.Boolean).annotate({
    description: "Grab service banners (--script=banner).",
  }),
})

export const Output = SecurityExec.Output

export const Plugin = {
  id: "opencode.tool.security.nmap",
  effect: Effect.fn("NmapTool.Plugin")(function* (ctx: Context) {
    const proc = yield* AppProcess.Service
    const permission = yield* Permission.Service

    yield* ctx.tool
      .transform((editor) =>
        editor.add({
          name,
          options: { codemode: false },
          description:
            "Scan a host or network with nmap: discover open ports, detect running services and versions, and optionally fingerprint the OS or grab banners. Use for authorized network reconnaissance.",
          input: Input,
          output: Output,
          execute: (input, context) => {
            const bin = SecurityExec.resolveExecutable(EXECUTABLES)
            if (!bin) return Effect.fail(SecurityExec.missingExecutableFailure(name, EXECUTABLES, DOCS_URL))
            const args = [
              "-sV",
              "-oX",
              "-",
              ...(input.ports ? ["-p", input.ports] : []),
              ...(input.osDetection ? ["-O"] : []),
              ...(input.bannerGrabbing ? ["--script=banner"] : []),
              input.target,
            ]
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
