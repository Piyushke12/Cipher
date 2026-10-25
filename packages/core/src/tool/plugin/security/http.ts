export * as HttpTool from "./http.js"

import type { Context } from "@opencode/plugin/effect/plugin"
import { ToolFailure } from "@opencode/ai"
import { Duration, Effect, Schema } from "effect"
import { HttpClient, HttpClientRequest } from "effect/http"
import { Permission } from "../../../permission.js"
import { collectBoundedResponseBody } from "../../http-body.js"

export const name = "http"

// Bounded so a runaway target can't blow memory, but large enough to cover real
// pentest responses - JS bundles, source dumps, big JSON/API payloads - without
// discarding them. The session's generic output truncation (ToolOutput.truncate)
// already bounds what's shown to the model and saves the full body to a file the
// model can grep; this cap only needs to be big enough to reach that stage.
const MAX_RESPONSE_BYTES = 10_000_000
const DEFAULT_TIMEOUT_SECONDS = 30
const MAX_TIMEOUT_SECONDS = 120

const Method = Schema.Literals(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
const Timeout = Schema.Finite.check(Schema.isGreaterThan(0), Schema.isLessThanOrEqualTo(MAX_TIMEOUT_SECONDS))

export const Input = Schema.Struct({
  url: Schema.String.annotate({ description: "URL to request." }),
  method: Schema.optionalKey(Method).annotate({
    description: "HTTP method. Defaults to GET, or POST when a body is given and method is omitted.",
  }),
  headers: Schema.optionalKey(Schema.Record(Schema.String, Schema.String)).annotate({
    description:
      'Request headers as a {"Name": "value"} object. Required (with a Content-Type entry) whenever `body` is set.',
  }),
  body: Schema.optionalKey(Schema.String).annotate({
    description: "Raw request body (e.g. a JSON string). Payload characters (quotes, `--`, etc.) need no escaping here - this is a real HTTP request, not a shell command.",
  }),
  followRedirects: Schema.optionalKey(Schema.Boolean).annotate({
    description: "Follow redirects. Defaults to true.",
  }),
  timeout: Schema.optionalKey(Timeout).annotate({
    description: `Timeout in seconds (maximum: ${MAX_TIMEOUT_SECONDS}). Defaults to ${DEFAULT_TIMEOUT_SECONDS}.`,
  }),
})

export const Output = Schema.Struct({
  status: Schema.Number,
  contentType: Schema.String,
  body: Schema.String,
})

export const description =
  "Issue a raw HTTP request with an arbitrary method, headers, and body - for verifying business-logic findings directly (login bypass, injection, IDOR/BOLA, auth checks) rather than through a scanner. Unlike `shell`+curl, the body is sent as-is with no shell quoting involved, so payloads containing quotes or special characters need no escaping. A non-2xx/3xx response is returned as evidence, not a tool failure - read the body/status yourself to judge success."

export const Plugin = {
  id: "opencode.tool.security.http",
  effect: Effect.fn("HttpTool.Plugin")(function* (ctx: Context) {
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
              if (input.body && !input.headers) {
                return yield* Effect.fail(
                  new ToolFailure({
                    message: "body is present but no headers were given: add a headers entry, e.g. {\"Content-Type\": \"application/json\"}.",
                  }),
                )
              }
              const hasContentType = Object.keys(input.headers ?? {}).some(
                (key) => key.toLowerCase() === "content-type",
              )
              if (input.body && !hasContentType) {
                return yield* Effect.fail(
                  new ToolFailure({
                    message: "body is present but headers has no Content-Type entry: add one, e.g. {\"Content-Type\": \"application/json\"}.",
                  }),
                )
              }

              yield* permission.assert({
                action: name,
                resources: [input.url],
                save: ["*"],
                metadata: input,
                sessionID: context.sessionID,
                agent: context.agent,
                source: { type: "tool", messageID: context.messageID, id: context.id },
              })

              const method = input.method ?? (input.body ? "POST" : "GET")
              let req = HttpClientRequest.make(method)(input.url)
              if (input.headers) req = HttpClientRequest.setHeaders(req, input.headers)
              if (input.body) {
                // HttpBody.text() defaults to "text/plain" and that wins over whatever
                // Content-Type header was set above - without this, a caller-supplied
                // "application/json" header is silently overridden, so a JSON body never
                // actually gets sent as JSON (and the server-side JSON body parser never runs).
                const contentType = Object.entries(input.headers ?? {}).find(
                  ([key]) => key.toLowerCase() === "content-type",
                )?.[1]
                req = HttpClientRequest.bodyText(req, input.body, contentType)
              }

              const response = yield* http.execute(req).pipe(
                Effect.timeoutOrElse({
                  duration: Duration.seconds(input.timeout ?? DEFAULT_TIMEOUT_SECONDS),
                  orElse: () => Effect.fail(new Error("Request timed out")),
                }),
              )
              const contentType = response.headers["content-type"] || ""
              // On overflow this fails the tool call outright rather than returning a fabricated
              // "HTTP 200" success with a placeholder body - a response too large to collect at all
              // is not evidence of anything, and silently discarding it misleads the model into
              // thinking the request succeeded with that content.
              const bodyBytes = yield* collectBoundedResponseBody(
                response,
                MAX_RESPONSE_BYTES,
                () => new Error(`Response body exceeds the ${MAX_RESPONSE_BYTES}-byte limit for this tool - use shell+curl with -o to save it to a file instead.`),
              )
              const result = {
                status: response.status,
                contentType,
                body: new TextDecoder().decode(bodyBytes),
              }
              return { output: result, content: `HTTP ${result.status}\n\n${result.body}`, metadata: { status: result.status } }
            }).pipe(Effect.mapError((error) => (error instanceof ToolFailure ? error : new ToolFailure({ message: `Unable to request ${input.url}`, error })))),
        }),
      )
      .pipe(Effect.orDie)
  }),
}
