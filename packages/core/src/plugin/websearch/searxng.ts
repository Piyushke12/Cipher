export * as WebSearchSearxng from "./searxng.js"

import { define } from "@opencode/plugin/effect/plugin"
import { Duration, Effect, Schema, Scope } from "effect"
import { HttpClient, HttpClientRequest, HttpClientResponse } from "effect/http"

// Local, self-hosted meta search (no API key): https://docs.searxng.org/dev/search_api.html
// Reads the base URL from SEARXNG_URL, defaulting to the common local docker port.
const endpoint = () => `${(process.env.SEARXNG_URL ?? "http://127.0.0.1:8888").replace(/\/$/, "")}/search`

const SearchResponse = Schema.Struct({
  results: Schema.Array(
    Schema.Struct({
      title: Schema.String,
      url: Schema.String,
      content: Schema.optionalKey(Schema.String),
    }),
  ),
})

export const Plugin = define<HttpClient.HttpClient | Scope.Scope>({
  id: "opencode.websearch.searxng",
  effect: Effect.fn("WebSearchSearxng.Plugin")(function* (ctx) {
    const http = yield* HttpClient.HttpClient
    yield* ctx.websearch.transform((editor) => {
      editor.add({
        id: "searxng",
        name: "SearXNG (local)",
        execute: (input) =>
          Effect.gen(function* () {
            const url = new URL(endpoint())
            url.searchParams.set("q", input.query)
            url.searchParams.set("format", "json")
            const request = HttpClientRequest.get(url.toString()).pipe(HttpClientRequest.acceptJson)
            const response = yield* HttpClient.withScope(HttpClient.filterStatusOk(http))
              .execute(request)
              .pipe(
                Effect.flatMap(HttpClientResponse.schemaBodyJson(SearchResponse)),
                Effect.scoped,
                Effect.timeoutOrElse({
                  duration: Duration.seconds(20),
                  orElse: () => Effect.fail(new Error("SearXNG web search request timed out")),
                }),
              )
            return response.results.slice(0, 10).map((item) => ({
              url: item.url,
              title: item.title,
              ...(item.content ? { content: item.content } : {}),
              time: {},
            }))
          }),
      })
    })
  }),
})
