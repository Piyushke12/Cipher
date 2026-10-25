---
name: CSRF and CORS Misconfiguration
description: Force a victim's browser to perform an unwanted state-changing action using their own authenticated session (CSRF), or read cross-origin responses that should be restricted (CORS misconfiguration). Use when testing any state-changing endpoint (forms, account changes, money/data mutations) for missing anti-CSRF protection, or when an API sets Access-Control-Allow-Origin and you need to judge whether that configuration is actually exploitable.
---

# CSRF and CORS Misconfiguration

## CSRF: does the server trust the session cookie alone?
A state-changing request (POST/PUT/DELETE, or a GET that mutates state - itself worth flagging separately) is vulnerable if the server accepts it based on the session cookie alone, with no second signal the attacker's page can't reproduce. Check in this order:
1. **Is there a CSRF token at all?** Strip it entirely and resend. If the request still succeeds, there's no real protection regardless of what the form markup suggests.
2. **Is the token actually tied to the session, or just "present"?** Some implementations only check that *a* token was submitted, not that it matches the one issued for *this* session - get a token from one account/session, use it on another request from a different session, and see if it's accepted.
3. **SameSite cookie attribute.** `SameSite=Strict` or `Lax` on the session cookie blocks most cross-site form/fetch submission by default in modern browsers - check the `Set-Cookie` header on login. `None` (or absent, on an older stack) means the cookie rides along with cross-site requests and CSRF is back in play regardless of token logic, unless something else compensates.
4. **Does the endpoint check `Origin`/`Referer`?** Some apps use this instead of a token. Test whether it's enforced strictly (missing header entirely, or a crafted `Origin` that merely contains the right domain as a substring, e.g. `https://target.com.attacker.com` or `https://attacker.com/?target.com`) bypasses it.

Proof of concept is a minimal auto-submitting HTML form or `fetch(..., {credentials:'include'})` hosted on a different origin, opened in a browser that already holds the victim's session cookie - demonstrating the request fires and succeeds cross-origin is the evidence, not just "the token check looks weak in the code path."

## CORS misconfiguration: the dangerous combination is credentials + reflected origin
A response header of `Access-Control-Allow-Origin: *` by itself is low-impact for anything requiring authentication, because browsers refuse to send credentials (cookies) on a `*`-origin response - the attacker can read only what an unauthenticated request would already return. The actually dangerous pattern is:
```
Access-Control-Allow-Origin: <reflects whatever Origin I sent>
Access-Control-Allow-Credentials: true
```
This means the browser *will* attach the victim's cookies to a cross-origin request from an attacker-controlled page, and the attacker's page *will* be allowed to read the response - full session-authenticated data exfiltration, not just a header curiosity. Confirm it precisely:
1. Send a request with `Origin: https://evil-test.example` (anything that isn't the real origin) and see if it's reflected verbatim back in `Access-Control-Allow-Origin`.
2. Check whether `Access-Control-Allow-Credentials: true` is present on that same response. If both hold, this is exploitable with a simple cross-origin `fetch` from any page the victim visits while authenticated.
3. Also test near-miss allowlists: does the check do a substring/suffix match (`endswith(".target.com")` matched by `evil-target.com`, or a regex missing an anchor) rather than exact match against a known-good list? These are just as exploitable as a blanket reflection.
4. `null` origin handling matters too - some CORS configs explicitly allow `Origin: null` (sent by sandboxed iframes, some redirect chains, and local file:// pages) as a convenience that becomes another bypass.

## What's NOT the finding
Don't report a bare `Access-Control-Allow-Origin: *` on a genuinely public, unauthenticated endpoint (a public API, static assets) as a vulnerability - that's often intentional and harmless. The finding is specifically: credentialed response + attacker-controlled or over-permissive origin reflection.

## Tools
- `http` to set an arbitrary `Origin` header precisely and inspect the exact response headers back
- `browser` to run an actual cross-origin PoC page against the live session and confirm the browser does what the headers imply it should

## Reporting
For CSRF: the exact endpoint, what protection (if any) existed, and the PoC that fired the action from a different origin using only the victim's ambient session. For CORS: the exact `Origin` sent, the exact `Access-Control-Allow-Origin`/`Access-Control-Allow-Credentials` values returned, and - this is the part that makes it a real finding rather than a header note - what sensitive data or action the combination actually exposes to a cross-origin attacker page.
