---
name: Prototype Pollution
description: Inject a property onto Object.prototype (or another shared prototype) via an unsafe merge/clone/assign operation, then find what downstream code reads that polluted property to turn it into XSS, SSTI/RCE, or an authorization bypass. Use on any endpoint that accepts a nested JSON body processed by a deep-merge/clone/extend utility, or any client-side code doing the same with URL/query data.
---

# Prototype Pollution

## The two-step shape: pollution is not the finding, the sink is
Setting `__proto__.isAdmin = true` (or similar) on its own proves nothing observable by itself - JavaScript objects already have whatever properties their prototype chain gives them, so "I set a property" has no impact until *something else in the application reads that property and trusts it*. Treat pollution-point discovery and sink discovery as two separate steps, and don't stop at the first.

## Step 1: find the pollution point
Look for any code path that recursively copies/merges attacker-controlled keys into an object without rejecting dangerous key names - a deep-merge/clone/extend utility (hand-written or from a library with a known-vulnerable version), a config-loading step that merges user input into defaults, a query-string-to-object parser that doesn't flatten nested bracket syntax safely.

Test with a JSON body (or, for client-side cases, query-string/URL fragment syntax the app parses into nested keys) containing one of:
```
{"__proto__": {"polluted": "yes"}}
{"constructor": {"prototype": {"polluted": "yes"}}}
```
Confirm pollution happened, not just that the request was accepted: if you have any way to read back application state influenced by `Object.prototype` (an unrelated endpoint returning a plain object whose keys now include `polluted`, or a client-side console check via the `browser` tool - `({}).polluted`), that's confirmation. Some frameworks sanitize the literal strings `__proto__`/`constructor`/`prototype` in JSON keys but miss the bracket-notation or array-index variants a particular parser accepts - if the straightforward payload is stripped, look at exactly how the merge function walks the object (recursively by key name, or by some other traversal) for a form it doesn't account for.

## Step 2: find the sink - this is the actual exploitation work
Once pollution is confirmed, the question becomes: what in this application reads a property it didn't explicitly set, and does something security-relevant with it? Work backward from impact you want to demonstrate, not forward from "what can I pollute":

- **Template engine options object**: many server-side template engines accept an options object for things like `allowProtoPropertiesByDefault`, `autoescape`, or a custom delimiter/escaper - if that options object is built by merging defaults with something touched by your pollution, you may be able to flip autoescaping off (escalating a would-be-sanitized value into a real XSS) or alter rendering behavior toward the `ssti` skill's territory.
- **HTML sanitizer configuration**: a sanitizer that reads its allowed-tags/allowed-attributes list from an object whose prototype you polluted can be made to allow a tag/attribute it would otherwise strip - directly enabling an XSS payload that would normally be blocked (pair with the `xss` skill once you find this).
- **Authorization/role defaults**: code that does `user.isAdmin || defaults.isAdmin` or reads a role/permission property that falls through to the prototype when not explicitly set on the instance - a direct privilege-escalation primitive if you can find it.
- **Library-specific known sinks**: some libraries (certain template/markdown/validation packages) have had documented prototype-pollution-to-RCE gadget chains in specific versions - if the app's dependencies are visible (via a supply-chain scan, exposed lockfile, or version banner), check whether a known version/library combination applies before reasoning about a chain from scratch.

## Client-side vs server-side
Client-side prototype pollution (via URL hash/query parsed by client JS) is lower severity by default - it affects only the victim who clicks a crafted link, and the usual payoff is bypassing a client-side security check (CSP-reporting config, a client-side sanitizer's allowlist) to land XSS. Server-side pollution (via a JSON body processed server-side) is higher severity because a single request can affect shared, process-wide state (`Object.prototype` is global to the Node process) - potentially affecting *other users'* requests handled by the same worker until it's restarted, which is worth noting explicitly when reporting a server-side finding.

## Confirming impact, minimally
Demonstrate the full chain once: pollute → trigger the specific downstream behavior (one XSS firing, one authorization check passing that shouldn't, one template rendering differently) → stop. Don't attempt to enumerate every possible polluted key or every possible sink once one chain is proven.

## Tools
- `http` for crafting the exact nested-JSON pollution payload
- `browser` + its console/JS evaluation for confirming pollution and chained execution client-side
- `semgrep`/`gitleaks`-adjacent source review (or dependency-version checks via `trivy`/`grype`) if the target's framework/library versions are visible, to check for documented sink gadgets rather than searching for one blind

## Reporting
State the exact pollution payload and injection point, the exact sink (what code reads the polluted property and what it does with it), and the concrete downstream impact demonstrated (XSS fired, auth bypassed, template behavior altered) - "I polluted `__proto__`" alone is not a reportable finding without a sink.
