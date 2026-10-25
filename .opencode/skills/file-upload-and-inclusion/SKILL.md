---
name: File Upload and File Inclusion
description: Turn an upload or a file-path/template parameter into code execution, arbitrary write, or disclosure - extension/content-type bypass, path traversal during storage (zip-slip-style archive writes), and Local/Remote File Inclusion (LFI/RFI). Use on any upload endpoint, any parameter that names a file/template/page/include/view, or any feature that later reads back something the user supplied a path for.
---

# File Upload and File Inclusion

These are grouped because they chain: an upload endpoint often becomes the write primitive, and an inclusion point elsewhere becomes the execute primitive. Finding one, check for the other nearby.

## Upload: bypass what's actually being checked, not what looks checked
Client-side restrictions (an `accept=` attribute, a dropdown of "allowed" types) are not server-side restrictions - test the server directly with `http`/`shell`+curl, never trust the UI's own gate. In rough order of how often each check is the *only* one present:

1. **Extension-only check**: rename a disallowed payload with an allowed extension, or append a double extension (`shell.php.jpg`, `shell.phtml`, `shell.pHp` - case variants sometimes slip past a case-sensitive blocklist).
2. **Content-Type-only check**: send the real payload bytes with a spoofed `Content-Type` header (`image/png`) - this costs nothing extra with the `http` tool.
3. **Magic-byte/content sniffing**: prepend a valid image header (e.g. the GIF89a magic bytes) before your real payload if the server sniffs content rather than trusting the header - some execution contexts (a `.php` file read by Apache, a polyglot GIF/JS for an `<img>`-loading context) don't care what follows the magic bytes.
4. **Null byte / path tricks in the filename**: `shell.php%00.jpg` (legacy stacks), or a filename containing `../` to control *where* the file lands, independent of what it's named.

A size-limited upload is not a dead end for code execution the way it is for a memory bomb (see the `resource-exhaustion` skill for that angle) - a working webshell is a few dozen bytes.

## Upload: arbitrary write via archive extraction (zip-slip)
If the endpoint accepts and extracts an archive (ZIP/TAR), the extraction logic - not the upload check - is the real target. Craft an entry whose name is a traversal path (`../../../var/www/html/shell.php`, or on Windows targets `..\..\inetpub\wwwroot\shell.aspx`) using any zip library that lets you set an arbitrary entry name (Python's `zipfile.ZipInfo(filename=...)`, or a raw zip-format write if the library normalizes paths). Confirm with a benign target first (overwrite or create a file you can read back, like a static asset) before attempting to land anything executable - this both proves the primitive and keeps impact minimal. A successful write to a web-served directory with an executable extension is the escalation path to full RCE.

## Finding the inclusion point
LFI/RFI shows up anywhere a parameter names a page, template, language file, or "include" - not just an obvious `?file=` or `?page=` query string. Use `ffuf`'s hidden-parameter mode (body/header fuzzing against a parameter wordlist) when nothing visible takes a path - `template`, `view`, `layout`, `lang`, `include`, `page`, `doc`, `report` are disproportionately likely. The `surface` tool's route inventory is a good first pass for candidate endpoints that render documents, generate reports, or serve localized content.

## LFI technique ladder
1. **Direct path**: `../../../../etc/passwd` (or `..\..\..\..\windows\win.ini` on Windows) - try first, then walk up traversal depth only once per guess; if it's not working after a couple of depths, the issue is usually prefix/suffix handling (see below), not depth.
2. **Prefix/suffix stripping bypass**: if the app prepends a base directory or appends an extension (`.php`), a null byte (`%00`, legacy PHP) or path-truncation tricks (long strings of `../` padded past the filesystem's path-length limit, on older stacks) can defeat the appended suffix. On a modern stack, look instead for a parameter that controls the *extension* separately from the base name.
3. **Wrapper/filter abuse** (PHP-specific but worth checking on any PHP target): `php://filter/convert.base64-encode/resource=<path>` to read source without executing it, `php://filter` chains for more advanced primitive upgrades, `data://` or `expect://` wrappers if `allow_url_include` is on - these turn a read primitive into disclosure of source you can then audit for more bugs, or sometimes straight into RCE.
4. **Log/session poisoning for LFI-to-RCE**: if you can get attacker-controlled PHP (or other server-side) code into a file the application already includes - a web server access log (inject it via a crafted `User-Agent`), a session file, an uploaded file whose content you control - then an LFI that reaches that file executes your code. This is the standard LFI-to-RCE chain when direct code upload is blocked but LFI alone "only" reads files.
5. **RFI**: if the include parameter accepts a full URL (not just a local path) and `allow_url_include`-equivalent behavior is on, host your payload and include it directly - confirm with a callback via `interactsh` or a request to your own `http`-tool-observable listener before assuming it's blocked.

## Confirming impact, minimally
- For upload-to-RCE: write and trigger a payload that returns a single innocuous proof (process id, hostname, a fixed string via command execution) - not a full shell session logged in the report.
- For zip-slip: confirm the write landed (re-read the overwritten/created file) before trying to escalate it to something executable.
- For LFI: reading one sensitive-but-expected file (a config file showing you're reading real application state, not a guess) is enough; don't walk the whole filesystem.

## Tools
- `http` for crafting exact multipart upload requests and inclusion-parameter requests without shell-quoting pain
- `ffuf` for hidden-parameter discovery when no visible field takes a file/template/path
- `surface` for finding upload and document/report-generation endpoints in the first place
- `interactsh` / nuclei's OOB mode to confirm RFI or any blind file-fetch behavior

## Reporting
State the exact bypass that worked (which check failed, with the precise payload/filename/entry path), the proof obtained (file written, file read, command executed), and whether it chains into RCE or stops at disclosure/write. Note which of the layered checks (extension, content-type, magic bytes, size) were present versus absent - that's what tells the fix (all four should be enforced server-side, independently).
