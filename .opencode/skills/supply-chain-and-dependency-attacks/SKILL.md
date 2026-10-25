---
name: Supply Chain and Dependency Attacks
description: Find vulnerable/outdated dependencies, dependency-confusion opportunities, leaked secrets in source or build artifacts, and typosquatting risk - anywhere source code, a container image, or a build pipeline is in scope rather than just a running black-box endpoint. Use when asked to assess supply-chain risk, audit dependencies, or when source/repo/container access is available alongside or instead of a live target.
---

# Supply Chain and Dependency Attacks

## The pipeline: enumerate, then match against known bad
This is the one skill where the right first move is almost always to run tools in sequence rather than probe by hand - the signal (a known-CVE package, a leaked key, a confusable package name) is mechanical and exhaustive search beats guessing.

1. **`syft` first** - generate an SBOM (or just enumerate packages) from the source tree, container image, or filesystem in scope. This tells you exactly what's actually present and at what version, which is the input every later step needs. Don't skip straight to a vulnerability scanner without first confirming what you're actually scanning - a scan against the wrong image tag or an unbuilt source tree gives a false sense of coverage.
2. **`grype` and/or `trivy`/`trivy-image` against that SBOM, the filesystem, or the image** - matches installed package versions against known-CVE databases. Run both if available; they don't always agree, and a CVE flagged by one but not the other is still worth a manual look rather than dismissal. Pay attention to whether a flagged CVE is actually reachable in how the app uses that dependency (a vulnerable function the app never calls is a lower-priority finding than one on a code path you can reach) - the scanner reports presence, not exploitability.
3. **`gitleaks` across source and git history** - a leaked credential/API key/private key in a commit that was later "removed" is still in history unless that history was rewritten and force-pushed; always scan full history, not just the current tree. A leaked key often doesn't even need an application vulnerability - it's a direct credential.
4. **`semgrep`** for custom rule matches a CVE database can't catch - hardcoded secrets in a form a secrets-scanner regex might miss, dangerous deserialization/`eval`-style patterns, or insecure crypto primitive usage introduced by a dependency's *recommended usage pattern* rather than the dependency itself being CVE-flagged.

## Dependency confusion: when is it actually worth checking
This only applies to **internal/private-looking package names** - a scoped package (`@company/internal-utils`), a name that reads like an internal tool, or an explicit reference to a private registry in a lockfile/config. The attack: if that package name was never actually published to the public registry the build tool falls back to, an attacker who publishes a same-named package there (often with a higher version number, since many resolvers prefer the highest version across registries unless scoping is enforced) gets it installed and executed during the victim's own build. Check:
- Does the lockfile/manifest reference a private registry at all, or does everything resolve to the public one by default?
- For any internal-sounding name, is it actually claimed on the public registry right now? If not, and nothing pins/scopes it away from public resolution, that's the exposure - not something to exploit destructively against someone else's registry, but worth flagging precisely with the exact package name and why it's unclaimed.
- Monorepo setups with many internal packages are higher-risk simply by having more candidate names.

## Typosquatting and outdated/abandoned dependencies
- A dependency name one character off from a popular package (transposition, hyphen/underscore swap, common misspelling) in a manifest is worth flagging even without proving malicious intent - it's evidence of either a supply-chain compromise already in progress or a install-time mistake waiting to be exploited by someone else registering the real typo.
- A dependency with no updates in years, especially one handling parsing/crypto/auth, is a risk multiplier even absent a specific CVE - note it, since "no CVE filed" often just means "nobody's looked yet," not "it's safe."

## Reporting
List each finding with the exact package name, installed version, the CVE ID (if CVE-based) or the specific unclaimed-name/leaked-secret evidence, and - critically - whether you confirmed the vulnerable code path is actually reachable from the application's own usage, or whether this is scanner-reported presence only. Don't attempt to actually register a dependency-confusion package name against a real public registry as part of testing - the finding is "this name is unclaimed and would resolve publicly," demonstrated by checking the registry, not by claiming the name yourself.
