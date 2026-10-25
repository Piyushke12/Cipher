---
name: NoSQL Injection
description: Bypass authentication, exfiltrate data beyond what a query should return, or execute server-side JS against a MongoDB-style (or similar document-store) backend. Covers both mechanisms - operator injection (client controls the query *structure*) and string/template injection into a server-built `$where`/expression (client controls only a *value* that's interpolated into code the server already wrote, needing SQL-injection-style quote-breakout) - plus array/type-confusion bypasses and brief notes on Elasticsearch/CouchDB equivalents. Distinct from relational SQL injection (see the `sqli` skill). Use when the backend is NoSQL/document-oriented, when a field accepts a request body you can shape as JSON, or when an endpoint's response includes more/other records than a single lookup should return (an order-tracking, "find by ID", or detail endpoint handing back a list, or rows that aren't yours).
---

# NoSQL Injection

## The two mechanisms - tell them apart before picking a payload
There are two fundamentally different ways attacker input reaches a NoSQL query, and they need opposite techniques. Confusing them is the single most common way an injection attempt that "looks right" still fails:

1. **Operator injection - the client controls the query *structure*.** The app does something like `find({ password: req.body.password })` and hands your JSON value straight to the query builder. Send an *object* (`{"$ne": null}`) where a string is expected - no quote-escaping involved, because there's no string literal to escape. This is what most people mean by "NoSQL injection" and is covered first below.
2. **Template/string injection - the client controls only a *value*, already embedded in code the server wrote.** The app does something like `find({ $where: "this.orderId === '" + id + "'" })` (or a template literal: `` `this.orderId === '${id}'` ``). Here `$where` is already hardcoded server-side - sending `{"$where": "true"}` as your value does nothing, it just becomes a literal string compared against `orderId`. **This needs a quote-breakout, exactly like classic SQL injection**: close the delimiter the server already opened, inject your own boolean logic, and - if there's trailing content after your injection point in the template - comment it out or re-balance it. If operator-style payloads on a `$where`-shaped endpoint all come back "no match" rather than an error, suspect this case before giving up on the endpoint.

## Operator injection via JSON body (the first thing to try)
If a login or lookup normally sends `{"email": "x@example.com", "password": "secret"}`, try replacing a value with an object invoking a query operator instead of a plain string:
```json
{"email": "admin@example.com", "password": {"$ne": null}}
{"email": {"$ne": null}, "password": {"$ne": null}}
{"email": {"$gt": ""}, "password": {"$gt": ""}}
{"email": {"$regex": "^adm"}, "password": {"$ne": null}}
```
`$ne: null` means "not equal to null" - almost any stored password hash satisfies that, so the check passes without knowing the real value. This is the direct NoSQL analogue of the SQL login-bypass comment-truncation trick in the `sqli` skill - same goal (authenticate without the real credential), different mechanism (operator substitution instead of string truncation). Try the same "site's own visible admin email" + an operator-injected password before anything more elaborate.

## When the client only ever sends strings (no JSON body available)
If the transport is a query string or form-encoded body rather than JSON, the application's own parser sometimes still turns bracket-notation into nested objects server-side (a common pattern in several web frameworks: `password[$ne]=1` gets parsed into `{password: {"$ne": "1"}}` before it ever reaches the database layer) - try the equivalent bracket syntax even when you can't send raw JSON:
```
email=admin@example.com&password[$ne]=1
```
This only works if the framework's body parser does that expansion; confirm by checking whether a deliberately malformed bracket expression changes the response (error vs. normal) before relying on it.

## `$where` as a client-controlled operator (mechanism 1)
Some document stores let the client send a raw `$where` clause that runs arbitrary JavaScript against each document - if any input reaches a `$where` expression this way (or an aggregation pipeline stage that accepts a raw expression), this is a code-execution-adjacent primitive, not just a filter bypass:
```json
{"$where": "this.password.length > 0"}
{"$where": "sleep(5000)"}
```
A deliberate delay (`sleep`) is a reliable, low-noise way to confirm `$where` actually executes your JavaScript (blind confirmation) even with no visible output difference - directly parallel to SQL's time-based blind technique.

## `$where` as a server-built template (mechanism 2) - quote-breakout
This is the more common real-world case and the one operator-injection payloads *can't* touch: the server already wrote the `$where` string itself, e.g. `` db.orders.find({ $where: `this.orderId === '${id}'` }) `` where only `id` is attacker-controlled. Recognize the shape first (an ID/lookup param feeding an endpoint whose response looks like it's filtering a collection by exact match), then:

1. **Identify the delimiter.** You usually can't see the server's source, so infer it: if a value with a single quote (`'`) in it causes a 500/error while a double quote (`"`) doesn't (or vice versa), that's the delimiter being broken unintentionally - confirms the quote character and that your input lands inside it unescaped.
2. **Close it, then inject a boolean.** Match the inferred delimiter exactly:
   ```
   ' || '1'=='1
   ' || 'a'=='a
   ```
   Applied to the example above, `id = ' || '1'=='1` turns the clause into `this.orderId === '' || '1'=='1'` - always true, matching every document instead of one. A payload using the *wrong* quote character (`"..."` against a `'`-delimited template) or missing the leading delimiter-closer entirely will silently fail as a literal string comparison - no error, just zero/one result, which is easy to misread as "not injectable" when it's actually "injectable, wrong syntax."
3. **If there's trailing template content after your slot** (e.g. `` `this.orderId === '${id}' && this.active === true` ``), either comment it out (`//` runs to end of line in JS, but only works if the whole `$where` string is a single line and nothing meaningful follows on later lines) or close your own clause and re-open a dummy one matching what follows, rather than assuming your injection is the last thing evaluated.
4. **If `||`-style boolean bypass returns too much/an error** (e.g. a type mismatch in whatever runs after your clause), fall back to blind extraction: inject a *conditional* instead of an always-true clause - `' + (this.email[0]=='a' ? '' : (1/0)) + '` or a `sleep()`-gated timing check per character - same escalation path as blind SQLi, just through a quote-breakout into JS instead of SQL.
5. **Confirm impact precisely**: a response that now contains more than one record (for a by-ID lookup) or a record that isn't yours (for an authenticated "my records" endpoint) is the proof - capture the count/ownership delta, not just "got a 200."

## `$regex` for blind, character-by-character extraction
Where no error-based or boolean oracle is available, `$regex` lets you extract unknown field values one character at a time by anchoring a regex and observing whether the response differs (match vs. no match):
```json
{"password": {"$regex": "^a"}}
{"password": {"$regex": "^ab"}}
```
Iterating this over the charset and position recovers the value without ever seeing it directly - mechanically identical to SQL's boolean-blind extraction, just expressed as a regex anchor instead of a `SUBSTRING()` comparison. This is tedious by hand; script the iteration (a short loop via `shell`) once the oracle is confirmed with one or two manual probes, rather than doing hundreds of requests by hand.

## Other operators worth the full set, not just `$ne`
Don't stop at `$ne`/`$gt`/`$regex` - if those are specifically sanitized/blocked, the rest of the operator family often isn't:
```json
{"role": {"$in": ["admin", "accounting"]}}
{"role": {"$nin": ["customer"]}}
{"email": {"$exists": true}}
{"$or": [{"role": "admin"}, {"role": "accounting"}]}
{"$and": [{"active": true}, {"email": {"$ne": null}}]}
```
`$exists` is useful for blind schema enumeration (does this document even have a field named X, without knowing its value). `$or`/`$and`/`$nor` let you build compound boolean-extraction primitives when a single operator is filtered, and are also a backdoor into boolean-blind data extraction when `$regex` specifically is blocked but other operators aren't.

## Array / type-confusion bypass
When `$ne`/`$gt` objects are specifically stripped by input validation (checking "is this value a plain string" and rejecting objects), try sending an **array** instead of an object - some validators only check `typeof value === 'object'` for *plain* objects and let arrays slip through, and some query builders treat `{field: [x, y]}` as an implicit `$in`. Also try arrays for fields a backend naively passes to a hashing/comparison function expecting a string (`password: ["a", "b"]`) - type coercion or an unhandled exception in the comparison step can itself produce a bypass (an uncaught error that falls through to a default-allow path is a real, recurring bug class here, distinct from the operator mechanism itself).

## Finding the injectable field in the first place
Don't limit testing to login forms - any field that becomes part of a database lookup is a candidate: search boxes, filters, "find by ID" lookups, sort parameters. If visible fields don't pan out, use `ffuf`'s hidden-parameter mode (body/header FUZZ against a parameter wordlist) the same way the `sqli` and `ssti` skills describe - the discovery technique is identical regardless of backend.

## Beyond MongoDB-style stores
The operator-vs-template distinction above generalizes, but the concrete syntax doesn't:
- **Elasticsearch**: a `query_string`/`script` field that embeds unsanitized input into a Painless/Groovy script (`"script": {"source": "doc['field'].value == '" + input + "'"}`) is the direct analogue of the `$where` template case - same quote-breakout approach, and genuinely code-execution-capable (Elasticsearch scripting is far more powerful than MongoDB's `$where`). A raw `query_string` query that passes through Lucene query syntax unescaped is the operator-injection analogue (inject `field:value OR *:*`-style boolean logic).
- **CouchDB**: the `_find` endpoint's `selector` is a JSON object much like MongoDB's query object - the same operator-injection techniques (`$ne`, `$gt`, `$or`) apply near-verbatim if the client can shape it.
- Don't assume "NoSQL" implies MongoDB specifically - check response headers/error pages/banners for the actual engine before picking syntax, the same way you'd fingerprint a SQL dialect.

## Confirming impact, minimally
An authentication bypass as an existing account (ideally admin) is self-evident, sufficient impact on its own - stop there rather than also extracting the database. For data exfiltration via quote-breakout or `$regex`/blind iteration, one clear over-disclosure (a record that isn't yours, or one field's extracted value) is enough to prove the primitive; a full dump isn't needed.

## Tools
- `http` for both mechanisms - the operator-injection payloads need exact JSON structure control; the quote-breakout payloads are plain strings but benefit from `http` keeping the raw body/URL exactly as typed, with no shell-quoting in the way of getting the delimiter character right
- `ffuf` for discovering which parameter is injectable when the visible fields don't work, and for scripting the character-by-character `$regex`/blind-conditional extraction loop once confirmed (or a short `shell` loop, whichever is more direct for the specific response-diffing needed)

## Reporting
State the exact field, the payload, and the result (status/response difference, or the count/ownership delta for over-disclosure) that proves the bypass or extraction. Name the specific mechanism involved - operator injection (`$ne`/`$gt`/`$in`-style), `$where`/script template quote-breakout, or `$regex`/blind-conditional extraction - since each drives a different fix: schema validation rejecting non-scalar input for operator injection, versus eliminating string-built `$where`/script expressions entirely (parameterize or drop the feature) for the template case, since there's no safe way to escape your way out of handing the server a string it evaluates as code.
