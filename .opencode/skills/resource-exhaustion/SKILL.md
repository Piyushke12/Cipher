---
name: Resource Exhaustion / Insecure Deserialization DoS
description: Crash or stall a server by feeding a parser (YAML/XML/JSON/ZIP) a small payload that expands into a huge in-memory structure - "memory bomb", "billion laughs", "YAML bomb", "decompression bomb", "entity expansion" - or by feeding a vulnerable regex a small input that makes it backtrack catastrophically ("ReDoS", ".*.*", ".+.+"). Use when asked about Insecure Deserialization, Denial of Service via file upload/parsing, regex/validation performance, or any endpoint that parses an uploaded/submitted document (YAML, XML, JSON, ZIP/archives) or matches user input against a server-side pattern.
---

# Resource Exhaustion via Deserialization ("memory bomb")

## The principle: amplify, don't enlarge
A size limit on the request body only defends against a payload that is big *on the wire*. It does nothing against a payload that is small on the wire and expands enormously *once parsed* - that gap is exactly what every real "memory bomb" / "billion laughs" technique exploits. If your first instinct is "make the uploaded file bigger," stop - that's the wrong axis, and it's usually what a size-capped endpoint is already defending against. The right axis is: make the file reference itself, or its own structure, repeatedly, so the parser's output is combinatorially larger than its input.

A classic mistake: generating a large *flat* file (e.g. a JSON/YAML list with thousands of plain entries) to approach a 100KB/1MB limit. That is linear data - parsing it costs roughly what it looks like it costs. It proves nothing about resource exhaustion and will never trigger the vulnerability, size limit or not.

## Technique 1: YAML billion-laughs (anchors + aliases)
YAML natively supports anchors (`&name`) and aliases (`*name`) - an alias is a *reference*, not a copy, but most parsers (including `js-yaml` even in "safe" mode) expand it fully when read into a normal data structure. Nest aliases-of-aliases and you get exponential blowup from a tiny file:
```yaml
a: &a ["x","x","x","x","x","x","x","x","x","x"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e,*e]
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f,*f]
h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g,*g]
i: &i [*h,*h,*h,*h,*h,*h,*h,*h,*h,*h]
j: [*i,*i,*i,*i,*i,*i,*i,*i,*i,*i]
```
This is ~500 bytes on disk and 10^10 string references once fully expanded - the expansion factor doubles (well, ×10s here) with every added level, so tune the fan-out and depth to stay under whatever upload size cap exists while still blowing past available memory. This is distinct from, and does not require, any dangerous custom tag (`!!js/function`, `!!python/object`, etc.) - a parser that correctly *blocks* dangerous tags (so it looks "securely configured" against RCE-via-deserialization) can still be fully exposed to this, because anchor/alias expansion is core YAML syntax, not an extension.

## Technique 2: XML entity expansion (classic billion laughs / XXE-DoS)
Same idea, with internal general entities:
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY a "lol">
 <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
 <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
 <!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
 <!ENTITY e "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;">
 <!ENTITY f "&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;">
 <!ENTITY g "&f;&f;&f;&f;&f;&f;&f;&f;&f;&f;">
 <!ENTITY h "&g;&g;&g;&g;&g;&g;&g;&g;&g;&g;">
 <!ENTITY i "&h;&h;&h;&h;&h;&h;&h;&h;&h;&h;">
 <!ENTITY j "&i;&i;&i;&i;&i;&i;&i;&i;&i;&i;">
]>
<lolz>&j;</lolz>
```
Many XML libraries (libxml2 included) now cap "entity amplification factor" specifically to block this - if you get an explicit error naming amplification/entity expansion, that defense is active; that is a finding in itself (confirms the library's awareness of the class, worth noting), but try the YAML and ZIP variants on the same target before concluding the class is unexploitable - defenses are rarely applied uniformly across every parser the app uses.

## Technique 3: decompression ("zip") bombs - get the ratio right
Two different shapes, and they test different things:
- **Nested archives** (zip-of-zips-of-zips, e.g. "42.zip"): only matters if the handler recursively extracts inner archives. If the handler extracts one level and stops (common - it's processing user-visible file contents, not walking an archive tree), nesting depth is wasted effort. Confirm recursive extraction before investing in a deeply-nested bomb.
- **Single highly-compressible file**: a file of repeated bytes (e.g. all zeros, or one repeated string) compresses at huge ratios - tens of KB of ZIP can represent tens or hundreds of MB decompressed. This matters whenever the handler extracts and reads file contents into memory at all (proven by *any* successful extraction - including something as unrelated-looking as a path-traversal/zip-slip write, which proves the entries get extracted and written). Maximize ratio by using one giant repeated-content entry rather than many separate files - decompression libraries generally allocate for the decompressed size of what they're currently extracting, and a single large entry forces one large allocation rather than many small ones that can be freed between files.

## Technique 4: ReDoS (regex catastrophic backtracking)
This one needs no parser, no file upload, and no size cap at all - it's reachable through *any* user input that gets matched against a server-side regular expression: input validation (email/username format checks), search, routing, even a WAF rule. It belongs in this file, not a separate skill, because it's the exact same principle as the other three: a tiny input, amplified by the engine's own processing into catastrophic cost.

The mechanism is nested/overlapping quantifiers whose backtracking search explodes combinatorially on a *non-matching* input. The classic shape is `(a+)+` or `(a|a)*` or `(.*)*` - any pattern where more than one way exists to partition the same run of characters across repeated groups. Feed it a long run of the character the groups are built on, followed by one character that breaks the match:
```
pattern: ^(a+)+$
input:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
```
Each extra `a` roughly doubles the backtracking engine's work before it gives up and reports no match - 30-40 characters is often enough to take a vulnerable engine from milliseconds to minutes. Scale the run length up incrementally (same principle as the other techniques: start small, confirm the trend, don't jump straight to a request sized to actually take the target down) and measure wall-clock response time at each step.

Where to look for the vulnerable pattern itself: anywhere input shape is validated with a regex rather than a proper parser - email/phone/URL format checks, username/slug character whitelists, and custom routing patterns are the recurring offenders. If the app is open-source or you can read its validation code, grep for the regex directly; black-box, submit inputs engineered to be maximally ambiguous for common validation shapes (repeated characters right before the position a required suffix/format marker would go) and watch for a response-time cliff rather than a size cliff.

## Confirming it's real exhaustion, not just acceptance
"The server returned 200/204 and didn't crash" is not evidence either way - weigh these signals instead:
- **Response latency**: a payload that's genuinely being parsed/expanded should take measurably longer than an equivalent-sized inert payload, even if well short of crashing. Always compare against a baseline request of similar wire-size with no amplification.
- **Process-level memory/CPU**, if you have any visibility into it (a health/metrics endpoint, container stats, `top`/`docker stats` on a system you're authorized to observe) - a real spike while the request is in flight is strong evidence.
- **A deliberately small/throttled version first.** Scale up incrementally (e.g. 5 levels of nesting before 10) rather than jumping straight to a payload sized to actually take the target down - per the minimum-impact principle, you want to demonstrate the mechanism, not necessarily execute a full DoS against a shared target.
- A 410/404/deprecated-endpoint response usually means the handler is gone or gated *before* parsing - but verify that: if a different error (unsafe-tag rejection, amplification-factor-exceeded, a stack trace naming the parser) appears for some payloads and not others on the *same* endpoint, the parser is in fact running, and the "deprecated" response is downstream of it, not a pre-parse short-circuit. If this is the case, the parse step already happened and already cost whatever it was going to cost, so time it directly.

## Tools
- `http` or `shell`+curl to submit the payload with the exact content-type/multipart form the target expects. Time the request explicitly (curl's `-w "%{time_total}\n"`, or compare wall-clock around the `http` tool call) rather than eyeballing it.
- A short local script (`write` + `shell`) to generate the YAML/XML/ZIP payload - these are a few lines each (see the YAML/XML templates above; for ZIP, compress one large repeated-content buffer with the standard library zip module in whatever language is on PATH).

## Reporting
State which parser/format was vulnerable (YAML anchors / XML entities / ZIP ratio), the exact payload shape and its wire-size vs. effective expansion, and the evidence of impact (measured latency delta, or observed memory/CPU, or an explicit crash/timeout) - not just "the server accepted it." Note any defense that *did* trigger (e.g. entity-amplification-factor rejection) as a mitigation already in place for that specific format, since it may not extend to the others.
