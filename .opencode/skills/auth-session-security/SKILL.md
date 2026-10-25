---
name: Authentication and Session Security
description: Take over another account when you need to act as a specific user (change their password, read their data, reach their role) without their password or SQL injection. Covers bearer-token verifier weaknesses (alg:none, HS256-signed-with-the-public-key / algorithm confusion, claim trust), missing re-authentication on password/profile changes, server-side token-session side effects, credential-recovery flows (forgot-password/security-question answer storage, seed data, spoofable rate-limit keys), password-reset token predictability and host-header-poisoned reset links, client-trusted "success"/2FA-passed response fields, OAuth misconfiguration (open redirect_uri, missing state/PKCE, implicit-flow token leakage), and SAML assertion forgery (signature wrapping, NameID injection, replay). Use when the blocker sounds like needing a token for a specific user, believing the token's signing algorithm prevents forgery, resetting a password through a recovery flow, or the target uses OAuth/SSO or SAML for login.
---

# Authentication and Session Security: account takeover without the victim's credentials

## The mistake to avoid
"I only have a token signed with RS256, so I cannot forge one for the victim" is backwards. The algorithm of tokens *you were issued* says nothing about what the *verifier* accepts. Ask instead: **what does the server trust when it decides who I am, and can I produce that?** Identity usually comes from one of four places, and only the first requires the victim:

1. A credential exchange (login) - needs the password.
2. A token signature check - test the verifier, not the issuer.
3. A server-side session map keyed by the token string - find who writes to it.
4. A client-supplied identifier (`userId`, `email`, `id` in the body) - try changing it.

## Step 1: model the identity path (read the code if reachable)
- Where is the token issued, what `alg`, and what claims does it carry (user id, email, role)?
- Which middleware verifies it on *every* request? Is a verified token cached into a map keyed by the token string, and is that cache what sensitive routes read instead of re-verifying?
- Does the sensitive action re-check the current credential, or does it trust the session?

That last question is often half the exploit: a route that changes a password from the session identity but only verifies the current password **if the parameter is present**.

## Step 2: test the token verifier
Before forging, decode a token you already hold: `alg`, `typ`, `kid`, and claims. A `kid` often names a key file, and the algorithm tells you which verifier weakness to try first.

Test in this order, against a normal authenticated endpoint and against the target action:

1. **`alg: none`** with an empty signature: `header.payload.` - needs no key material at all. If it is accepted, stop here; the rest of this step is unnecessary.
2. **Claim trust**: if any route reads role/id from an unverified `decode()` rather than `verify()`, or accepts an identity field in the body, forge/tamper the claim and skip signatures entirely.
3. **Algorithm confusion**: sign HS256 using the exact bytes of the RSA **public** key as the HMAC secret. PEM whitespace matters - try the file content exactly, then trimmed, then the base64 body only.
4. **Weak HMAC secret** if the app signs symmetric tokens with a password-like string (try values from source/config).

Version signals matter: older JWT libraries (roughly `jsonwebtoken < 9`, `jws < 3`, `express-jwt < 6`) are the usual reason 1-2 work.

### Finding the key, only if you need it
Only steps 3-4 require key material. This is a search for a secret in a public location, not recall of a product's layout - work the obvious locations mechanically:
1. **Standard/static locations**: `/.well-known/jwks.json`, `/jwks.json`, `/public.pem`, `/public.key`, `/cert.pem`, `/server.pem`, `/keys`, `/certs`. Run the path fuzzer with a key-oriented wordlist rather than guessing one path. Check whether any key/cert directory is browsable - a directory listing reveals filenames you could never guess.
2. **Everything you already downloaded**: grep bundles, source maps, backups, config files, and error pages for `-----BEGIN`, `"kty"`, `publicKey`, `PUBLIC KEY`, `.pem`, `.pub`, `jwt`. The surface inventory reports PEM/JWKS blocks it encounters.
3. **The stack's own source**: if the app identifies its framework/version (banner, stack trace, OSS project), read that version's code for how the public key is loaded and whether the directory is served statically, then request the same path. An exposed source/build file or backup often shows both the file name and the mount point.
4. **Error output**: stack traces and verbose errors frequently name key paths and the JWT library version.

Minimal HS256-with-public-key signer (Node/Bun):
```js
const fs = require("fs"), crypto = require("crypto")
const pub = fs.readFileSync("public.pem", "utf8")        // exact bytes, keep the trailing newline first
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url")
const now = Math.floor(Date.now() / 1000)
const head = b64({ alg: "HS256", typ: "JWT" })
const body = b64({ data: { id: VICTIM_ID, email: VICTIM_EMAIL, role: "customer" }, iat: now, exp: now + 21600 })
const sig = crypto.createHmac("sha256", pub).update(`${head}.${body}`).digest("base64url")
console.log(`${head}.${body}.${sig}`)
```
Mirror the claim shape of a token you obtained legitimately - don't invent fields the app does not read.

## Step 3: exploit the missing re-authentication
For every "change password / change email / add MFA / transfer" action, test omissions and type confusion, not just wrong values:
- omit the current/old credential field entirely
- send it empty, `null`, or duplicated (`current=a&current=b` -> array)
- send the new value twice for the confirmation field
- compare the *change* flow with the *reset* flow: one often forgets the check the other enforces

If the route reads identity from a token-to-user cache, send the forged token **directly to that action**: the caching middleware usually runs earlier in the same request, so no separate warm-up is needed. If it instead rejects a token that a normal endpoint accepts, you are hitting a cache lookup rather than a signature check - find which request registers the token, or use a route that verifies directly.

## Step 4: prove it, minimally
- Perform the single state change (e.g. set the victim's password to a known value).
- Verify by logging in as the victim (or re-reading the changed resource) - that is the evidence, not the 200.
- Stop. Do not dump the victim's data or change other accounts.

## Step 3b: credential recovery (forgot password / security questions)
Do not treat "the answer is not in the table I queried" as "the answer is unrecoverable", and do not make source access a precondition - the target is usually closed source.

1. **Disambiguate the account.** One person commonly has several accounts. Classify by the app's own mail domain (internal) versus webmail/third-party domains (external) and by role, not by display name; a missing security-question row is often the sign you picked the wrong account.
2. **Fingerprint the comparison black-box with a chosen-answer oracle.** Most apps let you set a recovery answer on your own account. Write a known answer **through the endpoint that stores answers** (registration/profile forms may silently ignore the field - test the dedicated answer endpoint), record the exact plaintext you sent, then read it back (the write/create response and list endpoints often return the stored value; if a "deny all" rule covers the list, test that rule with the token you already hold rather than accepting it as a boundary).
   - Write the **same answer to two accounts you own**: identical stored values mean no per-user salt - one deterministic global function (plain hash or HMAC with a global key). Different values mean a per-user salt. A salt you can read on your own row is **your** salt, not the victim's: the oracle transfers across accounts only in the no-salt/global case.
   - Write a **victim candidate as your own answer** and compare the returned value with the victim's stored value. Equality verifies the candidate even though you cannot compute the hash yourself. This removes any need to recover the key or read source. Do not stop at fingerprinting - replay the shortlisted candidates through the oracle. Naming the algorithm is not the deliverable; the verdict "recoverable or not" is decided by replay.
   - Confirm the victim's row actually exists in the **unfiltered** list before concluding it is absent; a filter parameter the API ignores returns a page, not the slice you requested, and that page is not evidence of absence.
3. **Generate a shortlist, not a brute force.** Use the question text, the objective's hints (OSINT, length/charset, person identity), and public facts. Verify each candidate through the oracle or a single reset attempt; a request per candidate is fine for dozens, not millions.
4. **Observe the rate-limit key.** If the limiter keys on `X-Forwarded-For`, email, session id, or a header, spoof or rotate that component. Send a few requests to learn the behavior; a 429 identifies the key, it does not close the flow.
5. **If writes are blocked**, look for other answer sinks: profile/registration fields that accept a recovery answer, admin APIs, exports, backups, alternate API versions, GraphQL, pagination/filter bypasses, and error bodies. Source/seed files are one sink among these - use them when reachable, not as the method.
6. Only when no oracle and no sink exists do you fall back to online attempts with a shortlist. Resolve any CAPTCHA/anti-automation parameter by reading what the handler actually validates. Then reset, prove with login, and stop.

## Other account-takeover vectors: reset tokens, host headers, and trusted responses
Not every takeover runs through a token verifier or a recovery-answer oracle. Three patterns recur:
- **Password-reset token predictability.** If the reset token looks like a timestamp, a sequential ID, a weakly-hashed user ID, or anything derivable from public info (username, email, registration time), request several resets for accounts you own and compare tokens for a pattern. A token space you can enumerate or compute is as good as no token.
- **Host-header injection into reset emails.** Many apps build the reset link from the request's `Host` header rather than a fixed server-side value (`https://${req.headers.host}/reset?token=...`). Send the reset request with a `Host` (or `X-Forwarded-Host`) pointing at a domain/listener you control; if the emailed link uses it, the victim's token leaks to you the moment they click it - no token-guessing needed at all.
- **Response-manipulation / client-trusted success.** Some flows (especially 2FA and multi-step verification) send a result field (`{"success": true}`, `{"step": "done"}`) that the *client* then trusts to decide whether to proceed, rather than the server re-checking state on the next request. Intercept and flip the field, or skip straight to the next step's endpoint - if the server accepts it without re-verifying, the check was decorative.

## OAuth misconfiguration
Identity here is decided by whichever party the app actually trusts at the end of the flow, not by OAuth's reputation for being "secure by design." Test:
- **`redirect_uri` validation.** If the app accepts any URI starting with, containing, or merely resembling the registered one (subdomain, path suffix, different TLD), register/point it at a host you control and harvest the authorization code or token when the IdP redirects there.
- **`state` parameter.** Missing or predictable `state` means the OAuth flow itself has a CSRF hole: you can start a login flow with your own account, capture the callback URL, and trick a victim into completing it - binding *their* session to *your* identity (login CSRF) or vice versa depending on the flow.
- **Implicit flow token leakage.** If the access token rides in the URL fragment/query of the redirect, it can leak via `Referer` headers, browser history, or any third-party script on the redirect landing page. Prefer-authorization-code-with-PKCE is the fix; its absence on a public client (SPA/mobile) is itself a finding.
- **Missing PKCE.** Without a `code_verifier`/`code_challenge` pair, an intercepted authorization code (e.g. via the redirect_uri issues above, or a malicious app sharing the same custom URI scheme on mobile) can be redeemed by anyone who captures it.

## SAML injection
SAML's trust model hinges entirely on signature validation covering the *right* element - these all abuse implementations that validate a signature but parse a different (unsigned or differently-scoped) part of the document:
- **XML signature wrapping (XSW).** Insert a forged, unsigned (or signature-stripped) assertion as a sibling/wrapper around the original signed one. A validator that checks "is there a valid signature somewhere in this document" rather than "is the specific assertion I'm about to process the one that's signed" will authenticate as whatever the forged assertion claims.
- **`NameID` injection.** Comment injection (`<NameID>admin<!--x-->@attacker.com</NameID>`) or null-byte tricks can make the signature-validation parser and the identity-extraction parser disagree about what the NameID actually is - sign as yourself, get processed as someone else.
- **Assertion replay.** If `NotOnOrAfter`/`NotBefore` aren't enforced, or there's no one-time-use tracking (`InResponseTo` correlation to a specific request), a captured assertion can be replayed indefinitely to re-authenticate as its subject.

## Pattern summary
The recurring shape is: asymmetric tokens issued, public key discoverable, an old verifier that accepts a symmetric signature made with that key, a token cache that treats "verified" as "this session", and a sensitive action that does not re-ask for the current credential. Any two of the last three are usually enough. Test each link independently - never conclude from the token's header algorithm that forgery is impossible.

## Evidence to report
- The token construction and the endpoint that accepted it (status only, don't paste secrets)
- The omitted or type-confused parameter on the sensitive action
- The post-condition proof (successful login as the victim / changed resource), then stop
