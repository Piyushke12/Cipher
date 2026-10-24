export * as BrowserTool from "./browser.js"

import type { Context } from "@opencode/plugin/effect/plugin"
import { Effect, Schema } from "effect"
import { fileURLToPath } from "node:url"
import { AppProcess } from "@opencode/util/process"
import { Permission } from "../../../permission.js"
import { SecurityExec } from "./exec.js"

export const name = "browser"
const EXECUTABLES = ["node"]
const DOCS_URL = "https://playwright.dev"
const SCRIPT = fileURLToPath(new URL("./scripts/browser-observe.mjs", import.meta.url))

export const Input = Schema.Struct({
  url: Schema.String.annotate({ description: "URL to load in a headless browser." }),
})

export const Output = SecurityExec.Output

export const Plugin = {
  id: "opencode.tool.security.browser",
  effect: Effect.fn("BrowserTool.Plugin")(function* (ctx: Context) {
    const proc = yield* AppProcess.Service
    const permission = yield* Permission.Service

    yield* ctx.tool
      .transform((editor) =>
        editor.add({
          name,
          options: { codemode: false },
          description:
            "Load a URL in headless Chromium (Playwright) and record network requests (XHR/fetch/document), returning discovered endpoints. Use for SPAs whose API surface is not visible in static HTML. Requires Node and the playwright package with Chromium installed.",
          input: Input,
          output: Output,
          execute: (input, context) => {
            const bin = SecurityExec.resolveExecutable(EXECUTABLES)
            if (!bin) return Effect.fail(SecurityExec.missingExecutableFailure(name, EXECUTABLES, DOCS_URL))
            const args = [SCRIPT, "--url", input.url, "--json"]
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
