---
name: Linux Privilege Escalation
description: Escalate from an initial low-privilege Linux foothold (shell access via RCE, SSRF-to-shell, or valid-but-limited credentials) toward root or a more privileged account. Use once you have any command-execution foothold on a Linux host and need to go from "I can run commands" to "I control the system" - this is what to actually DO after initial access, not recon theory.
---

# Linux Privilege Escalation

## Start with a fast, systematic sweep - don't guess
Before trying anything specific, run the cheap checks that cost nothing and often point straight at the answer:
```
id; whoami; uname -a
sudo -l
find / -perm -4000 -type f 2>/dev/null          # SUID
find / -perm -2000 -type f 2>/dev/null          # SGID
find / -writable -type d 2>/dev/null | grep -v '^/tmp\|^/proc'
cat /etc/crontab /etc/cron.d/* 2>/dev/null
ls -la /etc/cron.*/ 2>/dev/null
systemctl list-timers 2>/dev/null
```
Each one points to a distinct technique below - work from whichever actually returns something interesting rather than running every technique speculatively.

## sudo misconfiguration
`sudo -l` lists what the current user can run as another user/root, with or without a password. The common exploitable shapes:
- A binary listed that's known to allow breaking out to a shell when run with elevated privileges via its own built-in features (editors, pagers, interpreters, anything that can `!shell`, spawn a subprocess, or read/write arbitrary files as an argument) - the general category is "the binary itself provides a way to execute arbitrary commands or access arbitrary files," and which specific binaries currently qualify changes over time, so check what the listed binary's own documentation/help output actually allows rather than relying on a memorized list.
- `NOPASSWD` entries combined with a wildcard argument pattern (`/usr/bin/some-tool *`) - the wildcard is often exploitable by supplying an argument the tool wasn't meant to take (e.g. an option that reads/writes a file, or that itself invokes a shell).
- `LD_PRELOAD`/environment-variable passthrough still enabled in the sudoers config for a permitted command - lets you inject a malicious shared library into a process that then runs as the elevated user.

## SUID/SGID binary abuse
A SUID binary runs with its *owner's* privileges regardless of who invokes it. The two things to check for any SUID binary you find:
1. Does it let you break out to an arbitrary command (a binary whose normal function includes an escape hatch, same category as the sudo case above - pagers, editors, some admin utilities)?
2. Is it a **custom/in-house** SUID binary rather than a standard system one? These are far more likely to have an actual logic bug (path traversal, command injection via an argument, trusting an environment variable or relative path) than a hardened standard utility - prioritize auditing anything that isn't a well-known, widely-shipped binary.

For either case, confirm the owner is actually root (or another more-privileged account) before investing effort - a SUID bit on a binary owned by your own current user gains nothing.

## Writable root-owned automation (cron/systemd/PATH)
- A cron job or systemd timer/service file that runs as root and references a script or binary your current user can **write to** means your next edit of that file executes as root on its next scheduled run. Check both the job definition and the full path it invokes - a script owned by root but living in a directory your user can write into is just as exploitable as the script itself being writable.
- **Relative-path/PATH hijacking**: a root-run script that calls a command by bare name (not absolute path) and either runs with a PATH you influence, or runs in a working directory where you can drop a same-named executable earlier in the resolution order, executes *your* binary as root instead.
- Check for writable `/etc/ld.so.preload` or writable directories early in `LD_LIBRARY_PATH` for the same effect via shared-library injection on any root-run binary that loads from there.

## Kernel/capability-based escalation
A kernel version meaningfully older than current, or an unusual set of Linux capabilities granted to the current user/process (`getcap -r / 2>/dev/null`, or capabilities on the process itself) is a lead worth chasing, not something to exhaustively enumerate here - note the exact kernel version and any non-default capability, and check whether a known escalation exists for that specific combination before investing in exploit development. A capability like `cap_setuid` or an unexpectedly-granted `cap_sys_admin` on an accessible binary is frequently a faster, more reliable path than a kernel exploit.

## Minimal proof, every time
The proof of privilege escalation is a command run *as the higher-privileged account* with observable output proving it (`id` showing `uid=0`, reading a root-only file, writing to a root-owned location) - not just "the technique should theoretically work." Stop at that proof; per the minimum-impact principle, don't go on to modify system configuration, create new accounts, or install persistence beyond what's needed to demonstrate the escalation.

## Tools
- `shell` for every check above - this is almost entirely a shell-driven process
- `semgrep`/manual review if a custom SUID binary's source is reachable, to find the actual logic bug rather than just confirming the bit is set

## Reporting
State the exact mechanism (which sudo rule, which SUID binary and why it's exploitable, which writable file/cron entry, which capability), the exact command sequence used, and the proof of the elevated identity obtained. Note whether the root cause is a one-off misconfiguration (fixable by tightening that specific permission) or a pattern likely repeated elsewhere on the same host (worth a broader sweep, not just the one instance found).
