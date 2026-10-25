---
name: Request Smuggling and Cache Poisoning
description: Desynchronize a front-end proxy/load-balancer from the back-end server (HTTP request smuggling) or trick a cache into storing and replaying a malicious response (web cache deception/poisoning). Use when the target sits behind a reverse proxy, CDN, or load balancer, when responses are cached (Cache-Control, Age, X-Cache headers, or just suspiciously fast repeat responses), or when asked to test for desync/smuggling/cache attacks specifically.
---

# Request Smuggling and Cache Poisoning

## The shared mechanism
Both bugs come from two systems disagreeing about where one HTTP message ends and the next begins, or about which parts of a request determine whether a response can be reused for someone else. Smuggling disagrees *between two servers in the request path*; cache poisoning disagrees *between the cache and the origin* about what varies the response. Find the chain first (what's in front of what) before picking a technique - a single Node/Express app with no reverse proxy in front of it cannot have a smuggling bug at all, no matter how hard you look.

## Request smuggling: CL.TE / TE.CL desync
When a request carries both a `Content-Length` and a `Transfer-Encoding: chunked` header, the HTTP spec says `Transfer-Encoding` wins - but not every server enforces that, and the two systems in the chain often disagree:
- **CL.TE**: front-end honors `Content-Length`, back-end honors `Transfer-Encoding`. Send a chunked body that front-end thinks ends early (per `Content-Length`) but back-end keeps reading past that point as the start of the *next* request on the same connection, treating your crafted tail as someone else's request.
- **TE.CL**: the reverse - front-end honors `Transfer-Encoding`, back-end honors `Content-Length` and stops short, leaving bytes unconsumed that leak into the next request on that connection.

Minimal CL.TE probe (front-end forwards based on Content-Length=13, back-end re-reads the chunked body and finds a smuggled fragment after the terminating `0\r\n\r\n`):
```
POST / HTTP/1.1
Host: target
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```
Confirm via timing first, not content: send a request designed to make the back-end hang waiting for more data it'll never get (because the front-end already closed that logical request) - a measurable, repeatable delay on an otherwise-fast endpoint is the signal, cheaper and less destructive than trying to actually capture another user's request on a live connection pool. Also try obfuscated `Transfer-Encoding` variants (extra whitespace, duplicate header, `Transfer-Encoding: chunked` with a trailing tab, case variation) since many front-ends normalize the header differently than back-ends do, which is itself a desync even without the classic CL/TE mismatch.

Once timing confirms a desync, the payoff techniques are: smuggle a request that gets prepended to the *next* real user's request on a shared connection (response queue poisoning - you see their response, or they see yours), or smuggle a request to an internal-only endpoint the front-end would normally block by path.

## Web cache deception and poisoning
Two distinct bugs, don't conflate them:
- **Cache deception**: trick the cache into storing a page that should never be cached (because it's personalized/authenticated) by appending something the cache keys on differently than the origin does - classically a path suffix the origin ignores (serves the authenticated page regardless) but the cache's key-normalization treats as a static-looking resource (`/account/settings/nonexistent.css`, `/account/settings;.js`). If that gets cached, the *next* visitor who requests the same crafted URL gets the previous victim's authenticated response.
- **Cache poisoning via unkeyed input**: find a request header, cookie, or parameter that *affects the response* but is *not part of the cache key*. Common unkeyed inputs: `X-Forwarded-Host` (reflected into a canonical-URL `<link>` tag or a redirect, poisoning it site-wide), `X-Forwarded-Scheme`, `X-Original-URL`, a custom header the app trusts for feature flags, or even unnormalized query parameters. Send the payload once with a cache-buster, confirm the poisoned header is reflected and the response gets cached (check `Age`/`X-Cache: HIT` on an unauthenticated repeat request from a fresh session with no special headers), then confirm the cache actually serves it to a party who sent none of your crafted headers - that's the proof, not just "my own request got a poisoned response back."

## Confirming impact, not just a quirk
- For smuggling: demonstrate request queue poisoning against a second connection/session you control (two browser tabs, or two scripted clients), not just a timing anomaly - timing gets you to "there's a desync," but impact requires showing one party's traffic actually crossed into another's.
- For cache poisoning: demonstrate the poisoned response being served to a client that sent no special header at all. A single curl with and without the header, both followed by a plain repeat request, is enough.

## Tools
- `http` for exact control over headers (`Transfer-Encoding`, `Content-Length`, `X-Forwarded-*`) that `shell`+curl can mangle or auto-correct
- `shell`+curl with `-w "%{time_total}\n"` for the timing-based smuggling confirmation
- `browser` to open two independent sessions when confirming cross-user poisoning/queue effects

## Reporting
State the exact header combination and byte-for-byte request that triggered the desync or poisoned the cache, the mechanism (CL.TE/TE.CL, which unkeyed input, which cache-key mismatch), and the specific proof of cross-user impact - a second, unmodified client receiving the poisoned/smuggled response. Note which component (front-end, back-end, or the cache layer itself) is the one to fix, since the three failure points require different remediations.
