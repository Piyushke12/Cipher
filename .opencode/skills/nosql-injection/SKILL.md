---
name: NoSQL Injection
description: Bypass authentication or extract data from a MongoDB-style (or similar document-store) backend by injecting query operators instead of strings - distinct from relational SQL injection (see the `sqli` skill for that). Use when the backend is NoSQL/document-oriented, or when you don't know the backend but a login/search/filter field accepts a request body you can shape as JSON rather than a plain string.
---

# NoSQL Injection

## The core idea
Relational SQL injection works by breaking out of a string literal inside a query *written as text*. Most NoSQL injection is different: the query is already a data structure (commonly a JSON object), and the vulnerability is that the application passes attacker-controlled *structure* - not just attacker-controlled *values* - straight into the query builder. The attack is rarely "escape a quote"; it's "send an object where the server expects a string."

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

## `$where` and server-side JavaScript evaluation
Some document stores support a `$where` clause that runs arbitrary JavaScript against each document - if any input reaches a `$where` expression (or an aggregation pipeline stage that accepts a raw expression), this is a code-execution-adjacent primitive, not just a filter bypass:
```json
{"$where": "this.password.length > 0"}
{"$where": "sleep(5000)"}
```
A deliberate delay (`sleep`) is a reliable, low-noise way to confirm `$where` actually executes your JavaScript (blind confirmation) even with no visible output difference - directly parallel to SQL's time-based blind technique.

## `$regex` for blind, character-by-character extraction
Where no error-based or boolean oracle is available, `$regex` lets you extract unknown field values one character at a time by anchoring a regex and observing whether the response differs (match vs. no match):
```json
{"password": {"$regex": "^a"}}
{"password": {"$regex": "^ab"}}
```
Iterating this over the charset and position recovers the value without ever seeing it directly - mechanically identical to SQL's boolean-blind extraction, just expressed as a regex anchor instead of a `SUBSTRING()` comparison. This is tedious by hand; script the iteration (a short loop via `shell`) once the oracle is confirmed with one or two manual probes, rather than doing hundreds of requests by hand.

## Finding the injectable field in the first place
Don't limit testing to login forms - any field that becomes part of a database lookup is a candidate: search boxes, filters, "find by ID" lookups, sort parameters. If visible fields don't pan out, use `ffuf`'s hidden-parameter mode (body/header FUZZ against a parameter wordlist) the same way the `sqli` and `ssti` skills describe - the discovery technique is identical regardless of backend.

## Confirming impact, minimally
An authentication bypass as an existing account (ideally admin) is self-evident, sufficient impact on its own - stop there rather than also extracting the database. If demonstrating extraction specifically, pulling one field's value via `$regex`/blind iteration is enough to prove the primitive; a full dump isn't needed.

## Tools
- `http` for the operator-injection payloads - sending a JSON body with nested objects has no shell-quoting equivalent problem, but `http` keeps the exact Content-Type and structure under full control
- `ffuf` for discovering which parameter is injectable when the visible fields don't work, and for scripting the character-by-character `$regex` extraction loop once confirmed (or a short `shell` loop, whichever is more direct for the specific response-diffing needed)

## Reporting
State the exact field, the payload (operator used), and the result (status/response difference that proves the bypass or extraction). Name the specific operator class involved (`$ne`/`$gt`-style comparison bypass, `$where` JS evaluation, or `$regex` blind extraction) - that drives the fix recommendation, which is schema validation that rejects non-scalar input for fields that should only ever be strings, not escaping (there's no string to escape).
