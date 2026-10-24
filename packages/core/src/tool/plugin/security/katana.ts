export * as KatanaTool from "./katana.js"

import type { Context } from "@opencode/plugin/effect/plugin"
import { Effect, Schema } from "effect"
import { AppProcess } from "@opencode/util/process"
import { Permission } from "../../../permission.js"
import { SecurityExec } from "./exec.js"

export const name = "katana"
const EXECUTABLES = ["katana"]
const DOCS_URL = "https://github.com/projectdiscovery/katana"

export const Input = Schema.Struct({
  url: Schema.String.annotate({ description: "Starting URL to crawl." }),
  depth: Schema.optionalKey(Schema.String).annotate({ description: "Max crawl depth. Defaults to 3." }),
})

export const Output = SecurityExec.Output

export const Plugin = {
  id: "opencode.tool.security.katana",
  effect: Effect.fn("KatanaTool.Plugin")(function* (ctx: Context) {
    const proc = yield* AppProcess.Service
    const permission = yield* Permission.Service

    yield* ctx.tool
      .transform((editor) =>
        editor.add({
          name,
          options: { codemode: false },
          description:
            "Crawl a web application with katana to discover endpoints, including routes parsed out of JavaScript bundles, robots.txt, and sitemap.xml.",
          input: Input,
          output: Output,
          execute: (input, context) => {
            const bin = SecurityExec.resolveExecutable(EXECUTABLES)
            if (!bin) return Effect.fail(SecurityExec.missingExecutableFailure(name, EXECUTABLES, DOCS_URL))
            const args = [
              "-u",
              input.url,
              "-jsonl",
              "-silent",
              "-jc",
              "-kf",
              "all",
              ...(input.depth ? ["-d", input.depth] : []),
            ]
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
