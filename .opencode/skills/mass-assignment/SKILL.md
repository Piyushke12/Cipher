---
name: Mass Assignment
description: Send extra fields in a create/update request body - role, isAdmin, price, balance, verified, ownerId - that the client UI never exposes but the server binds straight onto a model anyway. Use on any endpoint that creates or updates an object from a JSON/form body (registration, profile update, checkout, admin-adjacent resources), especially where the response to a GET on the same resource reveals a field name the create/update form doesn't show.
---

# Mass Assignment / Over-Posting

## The mechanism
Many frameworks bind an incoming request body directly onto a model's fields by name, as a convenience - whatever keys you send that match a model attribute get set, whether or not the form/UI that's "supposed" to submit this request ever displays or allows editing that field. The vulnerability isn't a bug in any single field; it's the framework trusting the *shape* of client input to decide what's writable, instead of the server declaring an explicit allowlist of fields a given request is permitted to set. This means the attack is almost always: find a field name that exists on the model, and add it to a request that doesn't currently send it.

## Step 1: find candidate field names
You need field names the UI doesn't send, which means you can't just read the visible form:
- **Read a GET/list response for the same resource type.** It almost always returns fields the create/update form never asks for (`role`, `isAdmin`, `verified`, `createdAt`, internal IDs, pricing fields, ownership fields) - every key present in a read response is a candidate for the corresponding write.
- **Read the frontend bundle** (`surface` tool) for the model's type definition, form schema, or any serializer/DTO class name that hints at field lists beyond what's rendered.
- **Fuzz the request body itself.** `ffuf` with FUZZ as an extra JSON key in an otherwise-valid create/update body, against a generic wordlist (role, isAdmin, admin, verified, status, price, amount, balance, discount, owner, ownerId, userId, tenantId, isPaid, approved) - auto-calibration flags which added key changes the response (a validation error naming the field, a changed status code, or a changed value in a follow-up GET) from the baseline.
- **Compare two account roles' own profile/object payloads** if you have both - a privileged field on one model instance that's absent from the response of a lower-privileged one is a strong hint the field exists and is role-gated for *reads*, which says nothing about whether writes are gated the same way.

## Step 2: test the field, don't guess at its effect
Once you have a candidate key:
1. Send the normal, legitimate request first and capture the resulting object's full state via a follow-up GET.
2. Repeat the exact same request with the candidate key added (e.g. `"role": "admin"`, `"isAdmin": true`, `"price": 0`, `"ownerId": <someone else's id>`).
3. GET the object again and diff it against step 1's baseline - the field changing is the signal, independent of whether the write endpoint's own response echoes it back (many endpoints silently accept and apply a field without echoing it in their own response).
4. If the first candidate key doesn't work, try close variants - `role` vs `roles` vs `userRole` vs `accountType`, `isAdmin` vs `admin` vs `is_admin` - naming is inconsistent across read and write DTOs even within the same app.

## Common high-value targets
- **Registration/profile endpoints**: `role`, `isAdmin`, `accountType`, `verified`/`emailVerified` (skip a verification step entirely), `tier`/`plan` (free account gets premium fields).
- **E-commerce checkout/cart endpoints**: `price`, `unitPrice`, `discount`, `total` (set your own price), `quantity` combined with a per-unit price field (quantity validated, price not).
- **Ownership/relationship fields on update endpoints**: `ownerId`, `userId`, `createdBy`, `tenantId` - reassigning an object to yourself, or acting as if an object you don't own is yours, independent of any IDOR check on the object's *id* (this field manipulates the object's *ownership record itself*, which is a distinct bug from IDOR even though the end state looks similar).

## Tools
- `http` for precise control over exactly which JSON keys are present (omission matters as much as value - some frameworks only bind a field if the key is present at all, regardless of value).
- `ffuf` for discovering candidate field names in the request body when nothing's visible from a GET response.
- `surface` for pulling frontend type/schema hints out of JS bundles.

## Reporting
State the exact endpoint, the exact extra field and value sent, the before/after state of the object (not just the write response), and what that state change grants (role elevation, price manipulation, ownership change). If several similar fields are all mass-assignable on the same model, report the pattern once with the full list rather than as separate findings.
