---
name: IDOR / Broken Object-Level Authorization
description: Access, modify, or delete another user's data by changing an object identifier the server trusts without re-checking ownership - order IDs, user IDs, file IDs, invoice numbers, chat/conversation IDs, anything referencing "someone's thing" in a URL, body, or query string. Use whenever an endpoint takes an ID and the question is "does it check this ID belongs to me," not just "does it require login."
---

# IDOR / Broken Object-Level Authorization (BOLA)

## The core test
Authentication (do you have a valid session) and authorization (does this session own *this specific object*) are different checks, and a huge fraction of real apps only implement the first. For every endpoint that reads an ID from anywhere - URL path, query string, JSON/form body, even a header - test:
1. **Horizontal**: swap the ID for one belonging to a *different* user at the *same* privilege level. Does it return/modify their data instead of a 403/404?
2. **Vertical**: swap it for an ID that requires *higher* privilege (another role's resource, an admin-only record). More severe when it works.
3. **Existence oracle**: even if the content is blocked, does the response differ (404 vs 403, timing, error message) between "exists but not yours" and "doesn't exist"? That alone is an information-disclosure finding and tells you IDs are enumerable.

Create (or obtain) two accounts at the same privilege level specifically so you have a ground-truth "mine" vs "not mine" pair to diff against - don't rely on guessing whether a response looks wrong.

## Where IDs hide
Not just the obvious `/api/orders/1234`. Check every one of these per endpoint:
- Path segments (`/users/42/profile`)
- Query/body parameters (`?accountId=42`, `{"userId": 42}`)
- Nested references inside a larger object (an order object that embeds a `customerId`, `addressId`, `paymentMethodId` you can tamper independently of the order ID itself)
- Multipart/file endpoints keyed by a document or attachment ID
- GraphQL `id` arguments and node-lookup fields (`node(id: "...")`) - the field name differs but the vulnerability class doesn't
- WebSocket messages and any "subscribe to resource X" pattern

## ID enumeration and obfuscation
- **Sequential integers**: trivially enumerable - increment/decrement.
- **UUIDs**: not a fix by themselves if the UUID is *leaked* anywhere you already have access to (another endpoint that lists/returns objects you don't own even as metadata, a shared resource's member list, an error message, a `Location` header on creation, client-side JS/bundle referencing other users' IDs). Use `surface` and response-diffing to hunt for UUID leaks before assuming "random ID = safe."
- **Base64/encoded-looking IDs**: decode them; they're often just an encoded integer or a predictable composite (`userId:resourceId`), not random.
- **Hashids / short tokens**: check whether the encoding is deterministic and reversible with a known library (hashids, obscured-but-not-cryptographic schemes) before concluding it's unguessable.

## Method and verb matters
Authorization checks are frequently added to `GET` and missed on `PUT`/`PATCH`/`DELETE`, or vice versa - test every HTTP method the route plausibly supports, not just the one the UI uses. Also check that a 2xx on a write actually changed *your* view of the resource afterward (some broken implementations accept the write, apply it to the wrong record, or silently no-op) - verify with a follow-up read, don't trust the write's own status code.

## Mass-object endpoints
List/search/export endpoints that accept a filter (`?userId=`, `?accountId=`) are a faster way to confirm the same bug at scale once a single-object IDOR is proven - but per the minimum-evidence-necessary principle, stop at proving the boundary crosses (one other user's record), don't harvest the full dataset.

## Confirming impact, minimally
A successful cross-account read/write with the second account's data as evidence is the finding - screenshot or log the specific field that proves it's not your own (their email, their order total, something you didn't set). For a write/delete, verify the change (or the still-reachable 200 and a before/after read) rather than just the request's status code, then revert if it's a resource you can restore.

## Tools
- `http` for precise ID-swapped requests across every method the route supports - no shell-quoting friction for JSON bodies with nested object references
- `surface` to build the endpoint inventory first (source/source-path tagging shows which routes are POST-capable and likely to accept an ID) and to spot UUID/ID leaks in bundles or list responses
- `ffuf` with FUZZ over a numeric range or a captured ID list when you need to confirm an enumeration pattern across many IDs at once, held under a low rate if the target is shared
- `browser` when the object reference only appears after client-side routing/rendering (SPA deep links, a "my documents" view that fetches by ID client-side)

## Reporting
State the exact endpoint, method, the victim account's ID/identifier and what belonging-to-them evidence you observed, and whether it was read, write, or delete. Classify as IDOR (direct reference, no indirection at all) vs BOLA (an authorization check exists but is incomplete/bypassable) if the distinction is clear - it affects the recommended fix (introduce ownership checks vs. fix the existing check's logic).
