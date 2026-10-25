---
name: GraphQL Attacks
description: Attack a GraphQL endpoint specifically - schema discovery via introspection even when docs/playground are disabled, batching and aliasing to bypass per-request rate limits or brute-force protections, field-level authorization gaps that a mutation-level check misses, and deeply nested/circular queries that cost the server far more to resolve than they cost to send. Use whenever a target exposes `/graphql`, `/api/graphql`, or any endpoint accepting a `query`/`mutation` JSON body.
---

# GraphQL Attacks

## Step 1: map the schema, even with introspection "disabled"
Send a standard introspection query (`{ __schema { types { name fields { name } } } }`) first - it's often left on in non-production-looking deployments. If the full introspection query is blocked, don't assume the schema is hidden:
- Try a **partial introspection query** - some middlewares block the specific string `__schema` but not `__type`, or block the root query but not a query nested inside a fragment.
- **Field-suggestion errors**: most GraphQL servers return "Did you mean `xyz`?" on an unknown field name when running in non-strict error mode - probing single wrong field names and reading the suggestion rebuilds the schema one field at a time without introspection at all.
- Check the client-side JS bundle (the `surface` tool's bundle-scanning pass) for a baked-in schema file, persisted-query hash list, or Apollo/Relay query documents - frontend code frequently ships the exact queries/mutations it uses, including ones not reachable from the visible UI.
- `.graphqls`/`.graphql` schema files, or a `/graphql` GET request with no body (many servers serve GraphiQL/Playground/Voyager UI by default in anything but production).

## Step 2: batching and aliasing to bypass limits
A single HTTP request can carry many GraphQL operations at once - this defeats per-request rate limiting and brute-force lockouts that only count HTTP requests, not logical operations inside them:
- **Array batching**: send a JSON array of query objects instead of a single object, if the server supports it (`[{"query":"..."},{"query":"..."}]`).
- **Query aliasing**: send one HTTP request containing the *same* mutation/query repeated dozens of times with different aliases (`q1: login(...) q2: login(...) q3: login(...)`) - each alias is evaluated independently server-side, so this is effectively a password-spray or coupon-brute-force condensed into one request that a naive per-request limiter sees as "one attempt."
- If a login/reset/coupon endpoint is rate-limited over REST but reachable the same way over GraphQL, aliasing is usually the fastest way to prove the limiter doesn't cover this path.

## Step 3: field-level authorization gaps
Resolvers are often authorized individually, and it's common for the authorization check to live on the mutation that creates/returns a type, but not on every *field* of that type when reached a different way:
- Request a privileged field (`email`, `role`, `internalNotes`, `costPrice`) through a query path that wasn't the one the developer had in mind when they added the auth check - e.g. the field is protected on `user(id)` but not on the same field as returned inside `order.customer.email` or a search/list query that returns the same underlying type.
- Try the same mutation as different roles/sessions, and try a nested selection set that pulls fields spanning multiple underlying types/tables in one request - inconsistent authorization across the object graph is the norm, not the exception, because each resolver is usually authorized in isolation by whoever wrote it.

## Step 4: resource exhaustion via query shape
A GraphQL query's *cost* is a function of its depth and the fan-out at each level, not its size on the wire - a query that is small text can still force the server to resolve an enormous number of nested objects:
- **Deep nesting** on self-referential types (`user { friends { friends { friends { friends { ... } } } } }`) - if the schema has a recursive relationship, nest it well past anything the UI ever does.
- **Wide fan-out at each level**: request every field on every level of a list-returning query rather than one or two, multiplying the resolver calls.
- **Circular fragments**: a fragment that includes itself (where the schema and query validator allow it) can make a tiny query document expand into unbounded resolution work.
This is the same "small on the wire, huge once resolved" principle as the amplification techniques in the `resource-exhaustion` skill, just expressed through query structure instead of a file format - time the response and compare against a shallow/narrow baseline query of similar textual size, don't just note it got *a* response.

## Tools
- `http` to post raw query/mutation JSON bodies precisely, including batched-array and aliased variants.
- `ffuf` with FUZZ in the request body for discovering field names when neither introspection nor the field-suggestion-error trick works.
- `surface` to pull the frontend bundle(s) and extract any baked-in schema/query documents.

## Reporting
State which capability was abused (introspection left on, batching/aliasing bypassing a specific named rate limit, the exact field and query path that leaked data past its intended authorization, or the query shape and measured latency delta for a resource-exhaustion finding) and the minimum request that reproduces it. A schema dump by itself is reconnaissance, not a finding - pair it with the specific authorization or rate-limit bypass it enabled.
