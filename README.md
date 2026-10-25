<div align="center">

<h1>
  🛡️&nbsp;<span style="font-size:1.4em;letter-spacing:0.02em;">Cipher</span>
</h1>

**Autonomous Security Assessment Agent**

*Authorized penetration testing & vulnerability assessment*

[![Build status](https://img.shields.io/badge/build-passing-brightgreen?style=flat-square)]()
[![License](https://img.shields.io/badge/license-proprietary-blue?style=flat-square)]()

</div>

---

## 📖 Overview

**Cipher** is an autonomous security-assessment agent. Point it at an authorized target and it discovers, investigates, validates, and demonstrates security weaknesses the way an experienced offensive-security professional would — reasoning from observed evidence rather than guesswork, and reporting findings with proof instead of speculation.

Each step in an assessment asks:
1. What important facts are established?
2. What important security questions remain unanswered?
3. What attack paths are currently plausible?
4. Did the latest action reveal a new identity, privilege, resource, endpoint, API, or trust boundary?
5. Which capability would reduce the most important uncertainty?
6. Are prerequisites satisfied?
7. Is the expected information/security value worth the cost/risk?
8. If useful, execute the capability. If no meaningful safe investigation remains, propose completion.

**Core principles**
- Capabilities are instruments, not a checklist — never run a tool merely because it's available.
- Evidence hierarchy: observed facts > tool interpretations > hypotheses. Hypotheses are never presented as fact.
- When evidence supports a credible vulnerability, validate it and pursue meaningful impact when authorized and safe.
- When an action changes identity or privilege, reason about the newly reachable surface before continuing.

The goal is not to maximize the number of tools run, but to determine how far an attacker could realistically compromise the authorized system, and to produce strong evidence of that.

---

## 🧰 Capabilities

- **Offensive-security tools**: raw HTTP request/response inspection, attack-surface/endpoint inventory (robots.txt, sitemaps, OpenAPI specs, JS bundle analysis), recon search, and wrappers around `ffuf`, `nuclei`, `katana`, `exec`, and `shell` for black-box testing.
- **Evidence-first reasoning**: an assessment system prompt that separates established facts from hypotheses and tool interpretations, with explicit scope/authorization and prompt-injection guardrails.
- **Skill library**: 20 on-demand skills that load automatically when relevant, covering IDOR/BOLA, SSRF, XXE, SQL/NoSQL injection, SSTI, file upload/LFI/RFI, command injection, XSS, prototype pollution, GraphQL abuse, mass assignment, business logic flaws, race conditions/TOCTOU, request smuggling & cache poisoning, CSRF/CORS, resource exhaustion (YAML/XML/ZIP bombs, ReDoS), authentication & session security (JWT forgery, OAuth/SAML misconfiguration, account takeover), supply-chain/dependency attacks, LLM application attacks, and Linux privilege escalation.
- **Terminal UI** with a `build`/`plan` agent toggle and a `general` subagent for complex multi-step searches.

---

## 🚀 Running Locally

### Prerequisites

- [Bun](https://bun.sh) 1.4.4 or later
- Git

### Setup

```bash
git clone <this-repository-url>
cd opencode
bun install
```

### Start the agent

```bash
# Launch the TUI against the current directory
bun run dev

# Launch it against a specific project/target directory
bun run dev /path/to/project
```

> [!TIP]
> If you already have a Cipher background service running and just want to attach a dev build of the TUI to it, use `bun run dev:live` instead — it discovers the running service and reuses its session/storage channel.

### Verify your setup

```bash
bun run typecheck   # from a package directory, e.g. packages/core
bun run check       # full lint + typecheck from the repo root
```

---

## 🤖 Agents

Cipher includes two built-in agents you can switch between with the `Tab` key:

- **build** — default, full-access agent for running an assessment end-to-end
- **plan** — read-only agent for analysis and recon
  - Denies file edits by default
  - Asks permission before running shell commands
  - Ideal for scoping an engagement before taking action

Also included is a **general** subagent for complex searches and multi-step tasks, invoked internally or explicitly with `@general` in messages.

---

## 🛠️ Development

See [AGENTS.md](./AGENTS.md) for repository conventions (branch naming, commit style, code style, and testing). See [CONTRIBUTING.md](./CONTRIBUTING.md) for the contribution workflow.
