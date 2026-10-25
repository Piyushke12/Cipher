export * as SurfaceTool from "./surface.js"

import type { Context } from "@opencode/plugin/effect/plugin"
import { ToolFailure } from "@opencode/ai"
import { Duration, Effect, Schema } from "effect"
import { HttpClient, HttpClientRequest } from "effect/http"
import { Permission } from "../../../permission.js"
import { collectBoundedResponseBody } from "../../http-body.js"

export const name = "surface"

// Bundles are the densest source of hidden routes, but they are also the
// largest responses a target returns - keep a ceiling that still fits a
// typical SPA build while bounding memory.
const MAX_BODY_BYTES = 4_000_000
const REQUEST_TIMEOUT_SECONDS = 20
const DEFAULT_MAX_BUNDLES = 8
const DEFAULT_MAX_PATHS = 200
const MAX_OPTIONS_PROBES = 80
const MAX_SOURCE_BYTES = 4_000_000

const SEED_PATHS = [
  "/",
  "/robots.txt",
  "/sitemap.xml",
  "/swagger.json",
  "/openapi.json",
  "/api-docs",
  "/v2/api-docs",
  "/v3/api-docs",
  "/graphql",
  "/.well-known/jwks.json",
  "/jwks.json",
  "/public.pem",
  "/public.key",
]

const KEY_MATERIAL = /-----BEGIN ([A-Z0-9 ]*KEY)-----/
const JWKS_FIELDS = /"kty"\s*:/

const ASSET_EXTENSION =
  /\.(js|mjs|css|map|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|eot|otf|mp4|webm|mp3|pdf|zip|gz|tgz|br|wasm)$/i

// Any quoted string that starts with a slash is a candidate route. This is
// deliberately not restricted to /api or /rest: the routes most often missed
// during manual testing (top-level handlers, upload/report/export pages) do
// not sit under those prefixes.
const QUOTED_PATH = /["'`](\/[A-Za-z0-9._~\/-]{2,})/g
const HTML_ATTRIBUTE = /(?:href|src|action)\s*=\s*["']([^"']+)["']/gi
const SCRIPT_SOURCE = /<script[^>]+src\s*=\s*["']([^"']+)["']/gi
const SITEMAP_LOCATION = /<loc>\s*([^<\s]+)\s*<\/loc>/gi
const ROBOTS_RULE = /^(?:Allow|Disallow):\s*(\S+)/gim

const Endpoint = Schema.Struct({
  path: Schema.String,
  source: Schema.String,
  status: Schema.Number,
  contentType: Schema.String,
  bytes: Schema.Number,
  allow: Schema.String,
  rendersHtml: Schema.Boolean,
  sameAsRoot: Schema.Boolean,
})

export const Input = Schema.Struct({
  url: Schema.String.annotate({
    description:
      'Application root to inventory, e.g. "http://127.0.0.1:8080". Scheme and host are required; paths are seeded from the root plus robots.txt, sitemap.xml, and common API-description locations.',
  }),
  extraPaths: Schema.optionalKey(Schema.Array(Schema.String)).annotate({
    description: "Additional paths to include as seeds (absolute paths such as /admin or /reports).",
  }),
  maxBundles: Schema.optionalKey(Schema.Number).annotate({
    description: `Maximum script bundles to download and scan. Defaults to ${DEFAULT_MAX_BUNDLES}.`,
  }),
  maxPaths: Schema.optionalKey(Schema.Number).annotate({
    description: `Maximum discovered paths to probe. Defaults to ${DEFAULT_MAX_PATHS}.`,
  }),
  probe: Schema.optionalKey(Schema.Boolean).annotate({
    description:
      "Send a request to every discovered path to classify it (status, content-type, size, duplicate-of-root). Defaults to true.",
  }),
  maxSeconds: Schema.optionalKey(Schema.Number).annotate({
    description: "Overall time budget for inventory requests. Defaults to 120, maximum 600.",
  }),
})

export const Output = Schema.Struct({
  base: Schema.String,
  bundles: Schema.Array(Schema.String),
  endpoints: Schema.Array(Endpoint),
  counts: Schema.Struct({
    discovered: Schema.Number,
    probed: Schema.Number,
    html: Schema.Number,
    distinctBodies: Schema.Number,
  }),
  keyMaterial: Schema.Array(Schema.String),
  notes: Schema.Array(Schema.String),
})

type Fetched = {
  status: number
  contentType: string
  allow: string
  text: string
  bytes: number
}

type Row = {
  path: string
  source: string
  status: number
  contentType: string
  bytes: number
  allow: string
  rendersHtml: boolean
  sameAsRoot: boolean
}

const originOf = (url: string) => {
  try {
    const parsed = new URL(url)
    return parsed.origin
  } catch {
    return url.replace(/\/+$/, "")
  }
}

const resolve = (origin: string, reference: string) => {
  try {
    return new URL(reference, `${origin}/`).toString()
  } catch {
    return undefined
  }
}

const acceptPath = (candidate: string) => {
  const value = candidate.trim()
  if (!value.startsWith("/")) return undefined
  if (value.startsWith("//")) return undefined
  if (value.length < 2 || value.length > 300) return undefined
  if (value.includes("{{") || value.includes("${") || value.includes("%")) return undefined
  const path = value
    .split("?")[0]
    .split("#")[0]
    .replace(/[.,:;!?]+$/, "")
  if (!path || path === "/") return undefined
  if (/^\/\d+$/.test(path)) return undefined
  if (ASSET_EXTENSION.test(path)) return undefined
  if (/\/\*|\*\/|\[|\]|<|>/.test(path)) return undefined
  return path
}

const scan = (text: string, add: (path: string) => void) => {
  for (const match of text.matchAll(QUOTED_PATH)) {
    const path = acceptPath(match[1])
    if (path) add(path)
  }
}

const fingerprint = (text: string) => `${text.length}:${text.slice(0, 120)}:${text.slice(-120)}`

const keyMaterialKind = (text: string) => {
  const pem = text.match(KEY_MATERIAL)
  if (pem) return `PEM ${pem[1].trim()}`
  if (JWKS_FIELDS.test(text) && /"keys"\s*:/.test(text)) return "JWKS"
  return undefined
}

export const description =
  "Build a mechanical inventory of a web application's routes before testing. Fetches the root, robots.txt, sitemap.xml, and common API-description documents, downloads script bundles, and extracts every quoted path-like string (not just /api or /rest), then optionally requests each path to record status, content-type, size, advertised methods (Allow), and whether it returns real HTML or just the SPA shell. Use the returned list as a coverage ledger: renderer-style endpoints (HTML, POST-capable) are the first candidates for template/param tests."

export const Plugin = {
  id: "opencode.tool.security.surface",
  effect: Effect.fn("SurfaceTool.Plugin")(function* (ctx: Context) {
    const http = yield* HttpClient.HttpClient
    const permission = yield* Permission.Service

    yield* ctx.tool
      .transform((editor) =>
        editor.add({
          name,
          options: { codemode: false },
          description,
          input: Input,
          output: Output,
          execute: (input, context) =>
            Effect.gen(function* () {
              const base = input.url.replace(/\/+$/, "")
              const origin = originOf(base)
              if (!/^https?:\/\//i.test(origin)) {
                return yield* Effect.fail(
                  new ToolFailure({ message: `surface requires an absolute http(s) URL, got "${input.url}".` }),
                )
              }

              yield* permission.assert({
                action: name,
                resources: [base],
                save: ["*"],
                metadata: input,
                sessionID: context.sessionID,
                agent: context.agent,
                source: { type: "tool", messageID: context.messageID, id: context.id },
              })

              const notes: string[] = []
              const keyMaterial = new Map<string, string>()
              const noteKeys = (url: string, text: string) => {
                const kind = keyMaterialKind(text)
                if (kind && !keyMaterial.has(url)) keyMaterial.set(url, kind)
              }
              const bundles: string[] = []
              const sources = new Map<string, string>()
              const add = (candidate: string, source: string) => {
                const path = acceptPath(candidate)
                if (!path) return
                if (!sources.has(path)) sources.set(path, source)
              }

              const fetchOne = (url: string, method: "GET" | "OPTIONS" = "GET") =>
                http.execute(HttpClientRequest.make(method)(url)).pipe(
                  Effect.timeoutOrElse({
                    duration: Duration.seconds(REQUEST_TIMEOUT_SECONDS),
                    orElse: () => Effect.fail(new Error("Request timed out")),
                  }),
                  Effect.flatMap((response) =>
                    collectBoundedResponseBody(response, MAX_BODY_BYTES, () => new Error("body too large")).pipe(
                      Effect.map((body) => ({
                        status: response.status,
                        contentType: response.headers["content-type"] || "",
                        allow: response.headers["allow"] || "",
                        text: new TextDecoder().decode(body),
                        bytes: body.byteLength,
                      })),
                    ),
                  ),
                  Effect.catch(() => Effect.succeed(undefined as Fetched | undefined)),
                )

              const seeds = [...SEED_PATHS, ...(input.extraPaths ?? [])]
              const budgetSeconds = Math.max(5, Math.min(input.maxSeconds ?? 120, 600))
              const deadline = Date.now() + budgetSeconds * 1000
              const outOfTime = () => Date.now() > deadline
              let rootBody: string | undefined
              let rootFingerprint: string | undefined

              for (const seed of seeds) {
                if (outOfTime()) {
                  notes.push(`Stopped seed fetches at the ${budgetSeconds}s time budget.`)
                  break
                }
                const url = resolve(origin, seed)
                if (!url) continue
                const response = yield* fetchOne(url)
                if (!response) continue
                noteKeys(url, response.text)
                if (!rootBody && seed === "/") {
                  rootBody = response.text
                  rootFingerprint = fingerprint(response.text)
                }
                if (seed === "/robots.txt") {
                  for (const match of response.text.matchAll(ROBOTS_RULE)) add(match[1], "robots")
                } else if (seed === "/sitemap.xml") {
                  for (const match of response.text.matchAll(SITEMAP_LOCATION)) {
                    try {
                      const path = acceptPath(new URL(match[1], `${origin}/`).pathname)
                      if (path) add(path, "sitemap")
                    } catch {}
                  }
                } else if (
                  /json/i.test(response.contentType) &&
                  (/swagger|openapi/i.test(response.text.slice(0, 3000)) || /"paths"\s*:/.test(response.text))
                ) {
                  for (const match of response.text.matchAll(/"(\/[^"]*)"\s*:/g)) add(match[1], "api-description")
                  notes.push(`API description found at ${seed}`)
                }
              }

              if (rootBody) {
                for (const match of rootBody.matchAll(HTML_ATTRIBUTE)) {
                  const raw = match[1]
                  if (!raw || raw.startsWith("data:") || raw.startsWith("mailto:")) continue
                  const absolute = resolve(origin, raw)
                  if (!absolute) continue
                  const path = acceptPath(new URL(absolute).pathname)
                  if (path) add(path, "html")
                }
                for (const match of rootBody.matchAll(SCRIPT_SOURCE)) {
                  const absolute = resolve(origin, match[1])
                  if (absolute) bundles.push(absolute)
                }
                scan(rootBody.slice(0, MAX_SOURCE_BYTES), (path) => add(path, "html-inline"))
              } else {
                notes.push("Root did not return a readable body; inventory is limited to seed documents.")
              }

              const bundleLimit = Math.max(0, Math.min(input.maxBundles ?? DEFAULT_MAX_BUNDLES, 32))
              const uniqueBundles = [...new Set(bundles)].slice(0, bundleLimit)
              for (const bundle of uniqueBundles) {
                if (outOfTime()) {
                  notes.push(`Stopped bundle downloads at the ${budgetSeconds}s time budget.`)
                  break
                }
                const response = yield* fetchOne(bundle)
                if (!response) {
                  notes.push(`Bundle fetch failed: ${bundle}`)
                  continue
                }
                noteKeys(bundle, response.text)
                scan(response.text.slice(0, MAX_SOURCE_BYTES), (path) => add(path, "bundle"))
              }
              if (bundles.length > uniqueBundles.length) {
                notes.push(`Scanned ${uniqueBundles.length} of ${bundles.length} script bundles (maxBundles).`)
              }

              const discovered = [...sources.entries()].map(([path, source]) => ({ path, source }))
              const probe = input.probe ?? true
              const limit = Math.max(0, Math.min(input.maxPaths ?? DEFAULT_MAX_PATHS, 1000))
              const toProbe = discovered.slice(0, limit)
              if (discovered.length > toProbe.length) {
                notes.push(`Probed ${toProbe.length} of ${discovered.length} discovered paths (maxPaths).`)
              }

              const endpoints: Row[] = []
              const fingerprints = new Set<string>()
              if (rootFingerprint) fingerprints.add(rootFingerprint)

              for (const entry of toProbe) {
                if (outOfTime()) {
                  notes.push(`Stopped probing at the ${budgetSeconds}s time budget; the ledger is incomplete.`)
                  break
                }
                if (!probe) {
                  endpoints.push({
                    path: entry.path,
                    source: entry.source,
                    status: 0,
                    contentType: "",
                    bytes: 0,
                    allow: "",
                    rendersHtml: false,
                    sameAsRoot: false,
                  })
                  continue
                }
                const url = resolve(origin, entry.path)
                if (!url) continue
                const response = yield* fetchOne(url)
                if (!response) {
                  endpoints.push({
                    path: entry.path,
                    source: entry.source,
                    status: 0,
                    contentType: "",
                    bytes: 0,
                    allow: "",
                    rendersHtml: false,
                    sameAsRoot: false,
                  })
                  continue
                }
                noteKeys(url, response.text)
                const bodyFingerprint = fingerprint(response.text)
                const sameAsRoot = rootFingerprint !== undefined && bodyFingerprint === rootFingerprint
                if (!sameAsRoot) fingerprints.add(bodyFingerprint)
                const rendersHtml = /text\/html/i.test(response.contentType) && !sameAsRoot
                endpoints.push({
                  path: entry.path,
                  source: entry.source,
                  status: response.status,
                  contentType: response.contentType,
                  bytes: response.bytes,
                  allow: response.allow,
                  rendersHtml,
                  sameAsRoot,
                })
              }

              const optionsTargets = endpoints
                .filter((endpoint) => endpoint.status !== 0 && (endpoint.rendersHtml || endpoint.allow === ""))
                .slice(0, MAX_OPTIONS_PROBES)
              for (const endpoint of optionsTargets) {
                if (outOfTime()) break
                if (endpoint.allow !== "") continue
                const url = resolve(origin, endpoint.path)
                if (!url) continue
                const response = yield* fetchOne(url, "OPTIONS")
                if (response) endpoint.allow = response.allow
              }

              const html = endpoints.filter((endpoint) => endpoint.rendersHtml).length
              const counts = {
                discovered: discovered.length,
                probed: endpoints.filter((endpoint) => endpoint.status !== 0).length,
                html,
                distinctBodies: fingerprints.size,
              }

              if (html === 0 && counts.probed > 0) {
                notes.push(
                  "No probed path returned non-shell HTML. Server-rendered pages can still exist behind paths not present in bundles; treat this as incomplete, not as absence.",
                )
              }

              const ordered = [...endpoints].sort((a, b) => {
                const score = (endpoint: Row) =>
                  (endpoint.rendersHtml ? 4 : 0) +
                  (/post/i.test(endpoint.allow) ? 3 : 0) +
                  (endpoint.status >= 200 && endpoint.status < 400 ? 2 : 0) +
                  (!endpoint.sameAsRoot ? 1 : 0)
                return score(b) - score(a) || a.path.localeCompare(b.path)
              })

              const lines = ordered.map((endpoint) => {
                const flags = [
                  endpoint.rendersHtml ? "HTML" : "",
                  endpoint.sameAsRoot ? "shell" : "",
                  /post/i.test(endpoint.allow) ? "POST" : "",
                  endpoint.source,
                ]
                  .filter(Boolean)
                  .join(",")
                return `${endpoint.path}\t${endpoint.status || "-"}\t${endpoint.contentType || "-"}\t${endpoint.bytes}\t[${flags}]`
              })

              const keyList = [...keyMaterial.entries()].map(([url, kind]) => `${url} [${kind}]`)
              if (keyList.length) {
                notes.push(
                  `Key material (PEM/JWKS) found at ${keyList.length} location(s) - inspect it for signing/verification weaknesses.`,
                )
              }

              const content = [
                `Surface inventory for ${origin} - ${counts.discovered} paths discovered, ${counts.probed} probed, ${html} non-shell HTML.`,
                "Priority is: HTML renderers, then POST-capable endpoints, then the rest. Every probed endpoint is part of the coverage ledger - a class is only clear once its candidates here were tested.",
                "",
                "path\tstatus\tcontent-type\tbytes\t[flags]",
                ...lines,
                ...(keyList.length ? ["", "key material:", ...keyList.map((entry) => `- ${entry}`)] : []),
                ...(notes.length ? ["", "notes:", ...notes.map((note) => `- ${note}`)] : []),
              ].join("\n")

              return {
                output: {
                  base: origin,
                  bundles: uniqueBundles,
                  endpoints: ordered,
                  keyMaterial: keyList,
                  counts,
                  notes,
                },
                content,
                metadata: { discovered: counts.discovered, html: counts.html },
              }
            }).pipe(
              Effect.mapError((error) =>
                error instanceof ToolFailure
                  ? error
                  : new ToolFailure({ message: `Unable to inventory ${input.url}`, error }),
              ),
            ),
        }),
      )
      .pipe(Effect.orDie)
  }),
}
