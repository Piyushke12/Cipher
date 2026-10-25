---
name: Business Logic Flaws
description: Find vulnerabilities that have no payload at all - the server trusts an assumption about sequence, quantity, state, or ownership that a client can simply violate by calling things in a different order, with different numbers, or on someone else's behalf. Use when a target has a multi-step workflow (checkout, registration, password reset, approval/review flow, booking) and injection/auth testing alone hasn't surfaced anything, or when asked specifically about business logic.
---

# Business Logic Flaws

## There is no battery of payloads here
Every other skill in this collection centers on a string you send - `' OR 1=1--`, `{{7*7}}`, an extra JSON key. Business logic bugs are different: the request is syntactically and semantically valid, every field has a plausible value, and the bug is purely that the server didn't enforce an assumption about *how* the request fits into a larger process. You find these by modeling the intended workflow, then deliberately breaking each assumption it makes - not by trying harder payloads.

## Step 1: map the intended journey explicitly
Walk the real flow once as a legitimate user (the `browser` tool is useful here specifically because it shows you the sequence a human is meant to follow, including client-side steps that never touch the server). Write down, even just mentally: what state does each step assume exists before it runs, and what does it produce for the next step? A checkout flow assumes: cart has items -> address chosen -> payment method chosen -> order created -> payment captured -> order fulfilled. Each arrow is an assumption the server is trusting the client to have honored in order.

## Step 2: break every assumption, systematically
For each step in that chain, test:
- **Skip it.** Call the endpoint for step N+2 directly, with step N's expected prior state missing or stale. Many flows check "does this field exist" rather than "did the step that's supposed to set this field actually run."
- **Repeat it.** Call a step again after it already succeeded - a coupon-apply, a one-time discount, a "claim free item," a password-reset-token redemption, a review/vote submission. If it's meant to happen once per user/order/account, try firing it twice sequentially before trying it concurrently (concurrent repetition is a race condition - see the `race-conditions` skill - but *sequential* repetition is a pure logic bug if the server simply never checks "has this already happened").
- **Reorder it.** Confirm payment before address; redeem a coupon before adding the item it's supposed to discount; submit a review for an order that hasn't shipped.
- **Mutate a quantity/amount field past what the UI allows**: negative quantity (does it credit you instead of charging?), zero, a value larger than stock, a decimal where an integer is expected, a different currency/unit than the rest of the request implies.
- **Act on someone else's instance of the flow**, independent of any direct object-ID check - e.g. applying your coupon to someone else's cart via a cart/session identifier, or completing a multi-step action where only the *final* step's resource ID is checked, not whether the earlier steps in this chain belonged to the same user.

## Recurring concrete patterns worth testing specifically
- **Price/quantity manipulation**: a negative quantity, a price field present in the request at all when it should be server-derived, a "buy one get one" or bundle discount appliable repeatedly or stackable with itself, a currency-conversion step that rounds in the attacker's favor if you control which currency the request claims to be in.
- **Coupon/discount abuse**: reusing a single-use code (see also `race-conditions` for the concurrent variant), combining codes the UI presents as mutually exclusive, applying a code meant for a different user/account/region by simply submitting the code string you observed elsewhere (if the code itself, not an association to who it was issued to, is the only check).
- **Workflow-step skipping**: any multi-page wizard, approval chain, or checkout where intermediate pages exist purely as client-side UI state - call the final endpoint directly with the minimum fields it technically requires and see if the "earlier steps" were ever actually enforced server-side.
- **Trusting client-supplied sequencing without a true race**: a status field the client sends back verbatim (e.g. `"status": "approved"` in an update to a record the server should be computing approval for itself, not accepting as input).

## Confirming impact
A business logic finding is proven by the *state it produces*, not by a 200 response. Always confirm via a follow-up read of the affected resource (does the order total actually reflect the manipulated price? did the balance actually change? is the account actually in the skipped-step's "completed" state?) - a write endpoint returning success while silently ignoring or clamping your value is common, and worth noting as "attempted but not exploitable" rather than reporting as a confirmed finding.

## Tools
- `browser` to walk the legitimate flow once and capture the real sequence/state dependencies before testing deviations from it.
- `http` to call out-of-sequence or repeated steps precisely, including omitting fields a UI always sends.
- `surface` to find endpoints a client-rendered wizard calls that aren't reachable by clicking through the UI in the intended order.

## Reporting
Describe the intended flow in one or two sentences, then the exact deviation tested (skipped step / repeat / reorder / mutated value / cross-account) and the state change it produced, with before/after evidence from a resource read. Business impact (money, access, or data) is usually self-evident here - state it plainly rather than restating the mechanism twice.
