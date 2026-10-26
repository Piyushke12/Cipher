---
name: Custom Crypto & Token Replication
description: Forge a brand-new valid coupon code, signed blob, "continue code," or other app-specific derived value by reading the application's own encode/decode routine (and any embedded key/salt) and running that exact algorithm offline - not exploiting a bug in it, replicating a legitimate function so you can compute an output the server will accept. Use when a target issues codes, tokens, or blobs with no obvious format (not a standard JWT/UUID), the goal is to produce a *new* valid value from scratch rather than reuse or tamper with one you already have, and the app identifies itself as open-source or ships readable client/build artifacts.
---

# Custom Crypto & Token Replication

## This is a different move from "break the crypto"
Most crypto-adjacent testing (JWT algorithm confusion, weak HMAC secrets, predictable session tokens) is about finding a *flaw* in a scheme you can already see the shape of. This skill is for the other case: the app has a bespoke, closed-looking encoding (a coupon code, an internal "continuation" or state token, an encrypted blob embedded in a page) with no visible flaw to probe remotely, because there's nothing to fuzz - it's deterministic output of a function you don't have. The only way in is to find and run that exact function yourself, offline, with whatever key/salt it uses, and compute a value the server will accept as if it had generated it.

This is **source-reading for a legitimate routine**, not source-reading to hunt for a known vulnerable pattern (that's covered elsewhere). Don't let "don't go source-diving for a specific bug" guidance stop you here - replicating an app's own encode/decode function to produce a new valid output is exactly the technique these challenges require.

## Workflow
1. **Identify the candidate.** A code/token/blob that's short, looks structured (consistent length, charset, delimiters, or valid-base64-but-meaningless-decoded), and isn't a JWT, UUID, or anything else with a public spec. Discount/coupon codes, "resume where you left off" tokens, signed-looking HTML comments, and anything the app itself generates (not something a user set) are the usual candidates.
2. **Get the source.** If the target identifies itself as a known open-source project (banner, repo link, error trace, package.json in an exposed build artifact), clone or fetch the matching version. If not, check whether the client bundle itself contains the encode function (frontend-computed tokens are common for "obfuscated but not server-verified" schemes).
3. **Find the exact routine.** Grep for the field/param name, or for crypto primitives (`createHash`, `createHmac`, `createCipheriv`, a custom XOR/Caesar-style loop, `Buffer.from(..., 'base64')`) near code that constructs or parses the value. Read it fully - these are usually short, single-purpose functions.
4. **Find the key/salt.** It's almost always in the same source tree: a constant, a config file, an environment-variable default, or something derived from other already-public data (a product ID, a date, a username). If the scheme uses a secret that isn't visible from this source, this isn't a static-replication case - fall back to the JWT/weak-secret techniques in `auth-session-security` instead.
5. **Reimplement it exactly, then verify round-trip.** Before trying to produce a *new* forged value, reproduce a value you already have evidence of (decode a real code/token you observed) with your reimplementation and confirm it matches byte-for-byte. Only after that passes, change the input (discount percentage, target challenge number, claimed state) and compute the forged output.
6. **Submit the forged value through the real endpoint**, not just confirm it decodes - the proof is the server accepting it, not that your script produces plausible-looking output.

## Common shapes to recognize
- **Base64 of a delimited string with a checksum/HMAC suffix** - split on the last delimiter, everything before is the payload, the tail is a keyed or unkeyed hash of it.
- **Simple reversible transforms chained** (base64 -> XOR with a short repeating key -> reverse, etc.) - layered but not actually strong; each layer is individually easy to spot in source.
- **AES/DES with a key derived from non-secret data** (a product ID, a fixed app-wide string) - "encrypted" in name only once you have the source; this is still real crypto to implement, just with a known key.
- **A value encoding *state* rather than being validated against stored state** (e.g. a code representing "which steps/challenges are done" that the server decodes and trusts rather than looking up) - here the forged input is a semantically impossible/unearned state, not a modified existing one.

## Tools
- `shell` to clone/fetch source and to run your reimplementation (Node/Python, whichever the source's language is, for exact behavioral parity - don't port the algorithm to a different language's crypto library if you can just run the original)
- `gitleaks`/`semgrep`/`grep` equivalents to locate the key/salt fast across a large source tree
- `http` to submit the forged value and to re-fetch a real value for round-trip verification

## Reporting
Show the exact routine (file/function) you replicated, the key/salt and where it came from, your round-trip verification against a real value, and the forged input/output pair plus the server's acceptance of it. State plainly that this is a design weakness (trusting a client-presented derived value instead of a server-side lookup, or using a key/salt that isn't actually secret) rather than a traditional injection bug.
