export * as DnsxTool from "./dnsx.js"

import type { Context } from "@opencode/plugin/effect/plugin"
import { Effect, Schema } from "effect"
import { fileURLToPath } from "node:url"
import { AppProcess } from "@opencode/util/process"
import { Permission } from "../../../permission.js"
import { SecurityExec } from "./exec.js"

export const name = "dnsx"
const EXECUTABLES = ["dnsx"]
const DOCS_URL = "https://github.com/projectdiscovery/dnsx"
// dnsx fatals on domain input without -w; this is a small bundled default list,
// not a production wordlist — pass `wordlist` for real enumeration.
const DEFAULT_WORDLIST = fileURLToPath(new URL("./wordlists/subdomains.txt", import.meta.url))

export const Input = Schema.Struct({
  domain: Schema.String.annotate({ description: "Domain to resolve/brute-force subdomains for." }),
  wordlist: Schema.optionalKey(Schema.String).annotate({
    description: "Absolute path to a subdomain wordlist. Defaults to a small bundled sample list.",
  }),
})

export const Output = SecurityExec.Output

export const Plugin = {
  id: "opencode.tool.security.dnsx",
  effect: Effect.fn("DnsxTool.Plugin")(function* (ctx: Context) {
    const proc = yield* AppProcess.Service
    const permission = yield* Permission.Service

    yield* ctx.tool
      .transform((editor) =>
        editor.add({
          name,
          options: { codemode: false },
          description: "Fast DNS resolution and subdomain brute-forcing with dnsx.",
          input: Input,
          output: Output,
          execute: (input, context) => {
            const bin = SecurityExec.resolveExecutable(EXECUTABLES)
            if (!bin) return Effect.fail(SecurityExec.missingExecutableFailure(name, EXECUTABLES, DOCS_URL))
            const args = ["-d", input.domain, "-w", input.wordlist ?? DEFAULT_WORDLIST]
            return SecurityExec.runTool({
              proc,
              permission,
              name,
              resource: input.domain,
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
