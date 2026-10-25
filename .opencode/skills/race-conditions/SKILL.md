---
name: Race Conditions / TOCTOU
description: Exploit a check-then-act gap by sending many identical requests at the same instant instead of one at a time - redeem a single-use coupon more than once, buy more units than are in stock, withdraw/transfer more balance than exists, or claim a one-per-account reward repeatedly. Use whenever an action is supposed to be limited (one-time, capped by a balance, capped by stock) and sequential testing of it hasn't found a logic bug, or when asked about race conditions/TOCTOU/concurrency bugs specifically.
---

# Race Conditions / TOCTOU

## Why sequential testing never finds these
A race condition is a gap between a server *checking* a condition ("does this coupon still have uses left?", "is there still stock?", "is the balance sufficient?") and *acting* on it (decrementing the counter, debiting the balance). If that check and that act aren't atomic, firing requests one after another - even quickly by hand - gives the server time to fully complete request 1's check-and-act before request 2 arrives, so the condition is always correctly re-evaluated and nothing looks wrong. The gap is usually milliseconds wide. You can only find it by sending a batch of identical requests that genuinely land on the server at the same moment, not by sending them fast in sequence.

## Step 1: identify the limited action
Anything the application presents as "once," "limited," or "capped" is a candidate: redeem-coupon, claim-reward/claim-daily-bonus, add-to-cart-then-checkout against finite stock, transfer/withdraw against an account balance, vote/like (if capped to one per user), apply-for-a-limited-slot, use-a-single-use-token (password reset, invite code, discount code), upgrade-tier-for-free-trial. The common shape is: a counter or balance exists, the server reads it, decides "yes" or "no," and then writes an updated value back - read-decide-write.

## Step 2: fire genuinely concurrent requests
A loop with even a tiny delay between iterations is not a race condition test - it's a sequential retry that will reliably fail to reproduce the bug. You need requests dispatched together and awaited together. A minimal real example (Python, `aiohttp`):
```python
import asyncio, aiohttp

URL = "http://TARGET/api/redeem-coupon"
HEADERS = {"Authorization": "Bearer TOKEN", "Content-Type": "application/json"}
BODY = {"code": "SINGLE-USE-CODE"}
N = 30  # fire this many "simultaneous" attempts

async def attempt(session):
    async with session.post(URL, json=BODY, headers=HEADERS) as r:
        return r.status, await r.text()

async def main():
    async with aiohttp.ClientSession() as session:
        results = await asyncio.gather(*(attempt(session) for _ in range(N)))
        successes = [r for r in results if r[0] == 200]
        print(f"{len(successes)}/{N} succeeded")

asyncio.run(main())
```
If more than one of N identical requests succeeds where the server's own logic says at most one should, that's the race. `threading` with a `Barrier` to synchronize thread start is an equally valid alternative if `aiohttp` isn't available; a shell one-liner firing several `curl` calls backgrounded in the same instant (`curl ... & curl ... & curl ... & wait`) works as a quick first pass before writing a proper script, though a real async/threaded script gives far tighter timing and lets you scale N up when the window is especially narrow.

## Step 3: tune N and read the right signal
- Start with a modest N (10-30) - too few may never land close enough in time on a fast server; too many early on just makes triage slower.
- The signal isn't "did a request return 200" alone - check the *actual resulting state* (did the balance go negative or below what one legitimate redemption should leave; did stock go negative; did the coupon's use-count exceed its limit). Some endpoints return 200 to every request but only truly apply the effect once, which is correct behavior, not a race.
- If nothing reproduces, consider that the limiting resource might be sharded (e.g. per-region stock counters) - sending all N requests against the exact same session/account/resource ID matters; spreading them across different identifiers won't exercise the same lock/counter.

## Recurring high-value targets
- **Single-use codes/tokens**: coupon codes, invite codes, password-reset tokens, email-verification tokens - redeem the same one N times concurrently.
- **Stock/inventory limits**: add-to-cart-and-checkout for the last unit(s) of a limited item, fired concurrently from multiple sessions/carts if checkout is per-session.
- **Balance operations**: any transfer/withdraw/purchase that debits a balance - concurrent requests each checking "is balance >= X" independently can all pass the check before any of them writes the debit back.
- **Per-user-once actions**: claim-a-free-item, vote/like once, apply-for-something-capped - fire from the same authenticated session concurrently.

## Tools
- `shell` to run a short Python script (`asyncio`+`aiohttp`, or `threading`) - Python is on PATH; write the script with `write` and run it rather than inlining complex multi-line Python through the shell, which tends to hit interpreter/quoting friction.
- `http` for a single precise dry run of the request shape before scripting the concurrent version, so the script's request body/headers are already known-correct.

## Reporting
State the exact endpoint and limit that was supposed to apply (one redemption, N units of stock, balance >= 0), the number of concurrent requests sent and how many succeeded, and the resulting state that proves the limit was violated (use-count, stock count, or balance after). A race condition finding is only as credible as the state evidence - "N/30 requests returned 200" alone is suggestive but not proof; always pair it with the actual post-condition.
