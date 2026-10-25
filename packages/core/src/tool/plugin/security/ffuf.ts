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
// Small bundled sample wordlists, not production lists — pass `wordlist` for real coverage.
const DEFAULT_PATH_WORDLIST = fileURLToPath(new URL("./wordlists/common.txt", import.meta.url))
const DEFAULT_PARAM_WORDLIST = fileURLToPath(new URL("./wordlists/params.txt", import.meta.url))

export const Input = Schema.Struct({
  url: Schema.String.annotate({
    description:
      'Target URL. Put the literal "FUZZ" wherever you want values substituted - in the URL itself for path/endpoint discovery (e.g. "http://host/FUZZ" or "http://host/api/FUZZ"), or leave it fixed and put FUZZ in `body`/`headers` instead for parameter discovery.',
  }),
  method: Schema.optionalKey(Schema.String).annotate({
    description: "HTTP method. Defaults to GET, or POST when `body` is given and method is omitted.",
  }),
  body: Schema.optionalKey(Schema.String).annotate({
    description:
      'Request body template with "FUZZ" marking what to substitute - for hidden-parameter discovery, append a candidate param to a normal request, e.g. with known fields "email=x&securityAnswer=x&FUZZ=test" and a parameter-name wordlist. ffuf\'s auto-calibration (baseline vs. each response) flags which candidate name actually changes behavior - that difference is the finding, not any specific wordlist entry. A changed response on a name like "layout", "template", "view", "theme", "include", "file", "page", "path", "format", "redirect", "callback", or "debug" is worth investigating as a template/file-inclusion/debug-mode vector specifically.',
  }),
  headers: Schema.optionalKey(Schema.Record(Schema.String, Schema.String)).annotate({
    description: 'Request headers. "FUZZ" in a value fuzzes that header instead of the URL or body.',
  }),
  wordlist: Schema.optionalKey(Schema.String).annotate({
    description:
      "Absolute path to a wordlist. Defaults to a small bundled path sample for URL/path fuzzing, or a small bundled parameter-name sample (common hidden/debug param names) when `body` or `headers` contains FUZZ instead of `url`. Pass a real wordlist for actual coverage.",
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
            "Fuzz a web application with ffuf: discover hidden endpoints/paths by putting FUZZ in the URL, or discover hidden/undocumented request parameters (a common real vector for debug flags, template/layout injection, SSRF-via-redirect params, etc.) by putting FUZZ in `body` or `headers` instead. Auto-calibrates against baseline responses either way.",
          input: Input,
          output: Output,
          execute: (input, context) => {
            const bin = SecurityExec.resolveExecutable(EXECUTABLES)
            if (!bin) return Effect.fail(SecurityExec.missingExecutableFailure(name, EXECUTABLES, DOCS_URL))
            const fuzzesBodyOrHeaders =
              (input.body?.includes("FUZZ") ?? false) || Object.values(input.headers ?? {}).some((v) => v.includes("FUZZ"))
            const url = input.url.includes("FUZZ") || fuzzesBodyOrHeaders ? input.url : `${input.url}/FUZZ`
            const defaultWordlist = fuzzesBodyOrHeaders ? DEFAULT_PARAM_WORDLIST : DEFAULT_PATH_WORDLIST
            const args = [
              "-u",
              SecurityExec.normalizeLocalhost(url),
              "-w",
              input.wordlist ?? defaultWordlist,
              "-ac",
              "-s",
              ...(input.method ? ["-X", input.method] : input.body ? ["-X", "POST"] : []),
              ...(input.body ? ["-d", input.body] : []),
              ...Object.entries(input.headers ?? {}).flatMap(([k, v]) => ["-H", `${k}: ${v}`]),
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
