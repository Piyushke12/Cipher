export * as ExiftoolTool from "./exiftool.js"

import type { Context } from "@opencode/plugin/effect/plugin"
import { ToolFailure } from "@opencode/ai"
import { Duration, Effect, Schema } from "effect"
import { HttpClient, HttpClientRequest } from "effect/http"
import { randomUUID } from "node:crypto"
import { mkdtemp, rm, writeFile } from "node:fs/promises"
import os from "node:os"
import path from "path"
import { AppProcess } from "@opencode/util/process"
import { ChildProcess } from "effect/process"
import { FileAccess } from "../../../file-access.js"
import { Permission } from "../../../permission.js"
import { RelativePath } from "../../../schema.js"
import { collectBoundedResponseBody } from "../../http-body.js"
import { SecurityExec } from "./exec.js"

export const name = "exiftool"
const EXECUTABLES = ["exiftool"]
const DOCS_URL = "https://exiftool.org/"
const MAX_DOWNLOAD_BYTES = 50_000_000
const DOWNLOAD_TIMEOUT_SECONDS = 30
const NOTABLE_TAG = /gps|software|comment|author|creator|owner|hint|description|user|copyright/i

export const Input = Schema.Struct({
  url: Schema.optionalKey(Schema.String).annotate({
    description: "URL of a file to download and inspect (e.g. a product image or document the app serves). Give either url or path, not both.",
  }),
  path: Schema.optionalKey(RelativePath).annotate({
    description: "Path to a local file to inspect (e.g. something already downloaded). Give either url or path, not both.",
  }),
})

export const Output = Schema.Struct({
  fields: Schema.Record(Schema.String, Schema.String),
  raw: Schema.String,
})

export const description =
  "Extract EXIF and other embedded metadata (camera/software tags, GPS, author, comments, hidden fields) from an image, document, or other file via exiftool - give it a URL to download or a local path. Catalog assets that look unremarkable (product photos, attachments, exports) can still carry metadata that is the actual hint or leak: don't skip metadata inspection just because a file's name or thumbnail looks ordinary."

const downloadToTemp = (http: HttpClient.HttpClient, url: string) =>
  Effect.gen(function* () {
    const response = yield* http.execute(HttpClientRequest.get(url)).pipe(
      Effect.timeoutOrElse({
        duration: Duration.seconds(DOWNLOAD_TIMEOUT_SECONDS),
        orElse: () => Effect.fail(new Error("Download timed out")),
      }),
    )
    const bytes = yield* collectBoundedResponseBody(
      response,
      MAX_DOWNLOAD_BYTES,
      () => new Error(`Download exceeds the ${MAX_DOWNLOAD_BYTES}-byte limit for this tool.`),
    )
    const dir = yield* Effect.promise(() => mkdtemp(path.join(os.tmpdir(), "opencode-exiftool-")))
    const file = path.join(dir, randomUUID())
    yield* Effect.promise(() => writeFile(file, bytes))
    return { file, dir }
  })

const runExiftool = (proc: AppProcess.Interface, bin: string, filePath: string) =>
  Effect.gen(function* () {
    const result = yield* proc.run(ChildProcess.make(bin, ["-json", "-G", "-a", filePath], { extendEnv: true, stdin: "ignore" }), {
      timeout: SecurityExec.DEFAULT_TIMEOUT_MS,
      maxOutputBytes: 500_000,
      maxErrorBytes: 500_000,
    })
    const stdout = result.stdout.toString("utf8").trim()
    const stderr = result.stderr.toString("utf8").trim()
    if (result.exitCode !== 0 && !stdout) {
      return yield* Effect.fail(new ToolFailure({ message: `exiftool failed: ${stderr || `exit ${result.exitCode}`}` }))
    }

    const parsed = Schema.decodeUnknownOption(Schema.fromJsonString(Schema.Unknown))(stdout || "[]")
    const entry =
      parsed._tag === "Some" && Array.isArray(parsed.value) && parsed.value.length > 0
        ? (parsed.value[0] as Record<string, unknown>)
        : {}
    const fields = Object.fromEntries(
      Object.entries(entry)
        .filter(([key]) => key !== "SourceFile")
        .map(([key, value]) => [key, typeof value === "string" ? value : JSON.stringify(value)]),
    )
    const raw = Object.entries(fields)
      .map(([key, value]) => `${key}: ${value}`)
      .join("\n")
    const notable = Object.entries(fields).filter(([key]) => NOTABLE_TAG.test(key))

    const content = [
      raw || "(no metadata tags found)",
      notable.length ? `\nNotable tags: ${notable.map(([key, value]) => `${key}=${value}`).join(", ")}` : "",
      stderr ? `\n[stderr]\n${stderr}` : "",
    ]
      .filter(Boolean)
      .join("\n")

    return { output: { fields, raw }, content, metadata: { fieldCount: Object.keys(fields).length } }
  })

export const Plugin = {
  id: "opencode.tool.security.exiftool",
  effect: Effect.fn("ExiftoolTool.Plugin")(function* (ctx: Context) {
    const proc = yield* AppProcess.Service
    const permission = yield* Permission.Service
    const access = yield* FileAccess.Service
    const http = yield* HttpClient.HttpClient

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
              if (!input.url && !input.path) {
                return yield* Effect.fail(new ToolFailure({ message: "Give either url or path." }))
              }
              if (input.url && input.path) {
                return yield* Effect.fail(new ToolFailure({ message: "Give either url or path, not both." }))
              }

              const bin = SecurityExec.resolveExecutable(EXECUTABLES)
              if (!bin) return yield* SecurityExec.missingExecutableFailure(name, EXECUTABLES, DOCS_URL)

              const local = input.path ? yield* access.resolve({ path: input.path }) : undefined
              const resource = input.url ?? local!.absolute
              yield* permission.assert({
                action: name,
                resources: [resource],
                save: ["*"],
                metadata: input,
                sessionID: context.sessionID,
                agent: context.agent,
                source: { type: "tool", messageID: context.messageID, id: context.id },
              })

              if (local) {
                yield* access.authorizeExternal([local], context)
                return yield* runExiftool(proc, bin, local.absolute)
              }

              const { file, dir } = yield* downloadToTemp(http, input.url!)
              return yield* runExiftool(proc, bin, file).pipe(
                Effect.ensuring(Effect.promise(() => rm(dir, { recursive: true, force: true }))),
              )
            }).pipe(Effect.mapError(SecurityExec.toToolFailure(name))),
        }),
      )
      .pipe(Effect.orDie)
  }),
}
