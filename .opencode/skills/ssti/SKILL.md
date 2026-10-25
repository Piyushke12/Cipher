---
name: Server-Side Template Injection
description: Find and validate Server-Side Template Injection (SSTI) - user input evaluated by a server-side template engine, often leading to RCE. Use when testing any field that gets stored and redisplayed (profile/username fields, comments, feedback, generated documents/emails/PDFs, error pages, "preview" features), or when a `layout`/`template`/`view`-style parameter is discovered.
---

# Server-Side Template Injection (SSTI)

## What it is
A template engine (Handlebars/`hbs`, Pug/Jade, EJS, Jinja2, Twig, Freemarker, Velocity, Smarty, ERB...) renders user-controlled input as *template source*, not as plain data. Depending on the engine, this ranges from reflected output manipulation to full arbitrary code execution - template engines frequently expose eval-like primitives (Pug's `#{}` interpolation can call arbitrary JS; many engines allow iterating/accessing object prototypes to reach `require`/`eval`/`Process`).

## Where to look
Not just obvious "comment" boxes. Test every field that is stored and rendered back later, possibly on a *different* page than where it was submitted:
- Username / display name / profile fields (rendered on a profile, "welcome back", or admin user-list page)
- Any field feeding a generated document: email receipts, invoices/PDF exports, data-erasure/export confirmations, order confirmations
- Error pages / "nickname in the 404" style personalization
- A `layout`, `template`, `view`, `theme`, or `format` parameter discovered via hidden-parameter fuzzing (see the parameter-discovery technique below) - these often select or compose which template file renders, and are a direct, high-confidence SSTI vector when user-controlled at all

## Detection: the payload battery
Don't guess one syntax. Different engines use different interpolation syntax, so submit a polyglot/battery and check for **`49`** appearing anywhere in a *later* response (not just immediate reflection - it may render on a different page):
```
{{7*7}}          Handlebars, Jinja2, Twig (some)
${7*7}            JS template literals / some EL-based engines (often just reflects literally - low signal alone)
#{7*7}            Pug/Jade interpolation (also Ruby `#{}` in string interpolation contexts)
<%= 7*7 %>        EJS, ERB
@(7*7)            Razor
{{=7*7}}          Smarty-ish
${{7*7}}          Polyglot fragment covering multiple engines at once
```
If the field also feeds a filename, check `{{7*7}}.pdf`-style variants too - extensions can route to different renderers.

`#{...}` deserves special attention and is the one most testers skip: it's Pug/Jade's default interpolation, and several real-world apps extract it with a regex (`/#{(.*)}/`) and literally `eval()` the captured group server-side as a "feature" (template literal support for usernames), which is full RCE, not just "template rendered."

## Confirming it's real evaluation, not just reflection
- `49` appearing where you put `{{7*7}}` = confirmed evaluation (`7*7` wasn't computed by accident).
- Try an asymmetric payload like `{{7*8}}` vs `{{7*7}}` to rule out a coincidental "7*7" string match in some unrelated code path.
- Escalate incrementally, not straight to a destructive payload: arithmetic → `process.version`/`global`/engine-identifying read-only property → (only with explicit authorization for deeper validation) a read-only `require('os').hostname()`-style call. Stop at the minimum needed to prove impact per the scope rules - don't jump straight to `child_process.execSync` unless the user asked for that level of validation.

## Finding the injection point itself (parameter discovery)
Many SSTI-via-config-parameter bugs (a `layout`/`template`/`view` field controlling which file renders) aren't in any visible form - they're hidden/undocumented parameters on an otherwise-normal endpoint. Use `ffuf` with FUZZ in the request body against a parameter-name wordlist (the bundled `params.txt` the `ffuf` tool ships with is biased toward exactly these names), holding the endpoint's known-required fields constant:
```
ffuf: url=<endpoint>, method=POST,
      body="<known_field1>=x&<known_field2>=x&FUZZ=test"
```
Auto-calibration flags whichever candidate name changes the response from baseline. A hit on `layout`/`template`/`view`/`theme`/`include` is worth testing with a file path (`../../../some/file/with/a/real/extension`) for local file read/inclusion (see also: file-inclusion techniques - a template "layout" option often resolves relative to a views directory and may force an extension onto what you supply, so a path whose target already has an extension sometimes bypasses that).

## Engine-specific RCE escalation (only with explicit authorization)
Confirming arithmetic evaluation proves the bug; it doesn't prove impact. Going from "the template engine evaluates my input" to actual command execution needs an engine-specific gadget chain - only pursue this with explicit authorization for RCE-level validation, and stop at the minimum needed to prove it (a single `id`/`whoami`-equivalent read), per this skill's existing escalation-gating above:
- **Jinja2/Python**: no direct `eval`/`import` in the sandbox, so walk the object graph from any object's `__class__` to find a subprocess-capable class: `{{ ''.__class__.__mro__[1].__subclasses__() }}` lists every loaded subclass of `object`; grep the output for something like `subprocess.Popen` or a class exposing `__init__.__globals__`, then instantiate/call through it. The exact index into `__subclasses__()` output shifts between Python versions and loaded modules, so this is enumerate-then-pick, not a fixed one-liner.
- **Freemarker (Java)**: `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` - the `Execute` utility class is a documented, intentional "run a shell command" primitive that's still reachable if the app hasn't explicitly blacklisted it.
- **Velocity (Java)**: no built-in execute primitive like Freemarker's, so the path is via Java reflection from an accessible object: obtain a `Class` reference (e.g. via `$obj.class`), navigate to `Runtime`/`ProcessBuilder`, and invoke it reflectively. More brittle and app-specific than the Freemarker path - expect to adapt based on what objects are actually exposed in the template context.

## Tools
- `http` for crafting the exact request (method/headers/body, no shell-quoting issues with payloads containing quotes/braces)
- `ffuf` (body/header fuzzing mode) for hidden-parameter discovery
- `browser` when the trigger needs a rendered page you can't easily reproduce with a raw request

## Reporting
State the exact field, exact payload, and exact proof (the evaluated value and where it appeared). Note the engine if identifiable (syntax used + any error messages leaking engine name). Flag as Critical if you reached beyond arithmetic into runtime/process information or further - that's effectively RCE, not "just" injection.
