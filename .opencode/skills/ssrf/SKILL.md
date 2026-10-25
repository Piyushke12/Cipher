---
name: Server-Side Request Forgery
description: Make the server itself issue a request to a destination you choose - reaching internal-only services, cloud metadata, or localhost-bound admin ports the server can see but you can't. Use whenever an endpoint takes a URL, hostname, or anything that gets fetched/rendered/proxied server-side - webhooks, "import from URL," URL preview/unfurl, PDF/image generation from a URL, avatar-by-URL, XML/document upload that can reference an external resource, or any proxy/fetch-relay feature.
---

# Server-Side Request Forgery (SSRF)

## The core idea
Any feature where the server fetches a URL *on your behalf* is a potential pivot point: the request leaves from the server's network position, not yours, so it can reach things you can't reach directly - internal admin panels, databases listening on localhost, other containers/services on a private network, and cloud metadata services. The parameter doesn't have to be literally named `url` - check anything that could resolve to a network destination: a hostname, an image/avatar source, a callback/webhook field, a "import from" field, an XML document that can declare an external entity (see the `xxe-and-xml-attacks` skill - SSRF-via-XXE is the same bug through a different door).

## First: find out what's actually reachable
Point the target at an endpoint you control (or an OOB catcher) before trying anything sensitive - confirm the request fires at all, and what it reveals:
- Use `interactsh` (or `nuclei` with `-oast` enabled) to get a unique callback domain, feed it into the suspected parameter, and watch for an inbound DNS/HTTP hit - this confirms blind SSRF with zero reliance on response content.
- If the response *does* reflect something (status code, timing, partial body, error message naming a connection failure vs. a parse failure), that's a semi-blind oracle - a "connection refused" vs. "timeout" vs. "200 but garbage body" distinction alone can map internal ports.

## Where to point it once confirmed
- **Loopback and link-local**: `127.0.0.1`, `localhost`, `0.0.0.0`, `[::1]` - scan a short list of common internal ports (admin panels, databases, internal APIs) through the SSRF rather than guessing one.
- **The cloud metadata service**: most cloud providers expose an instance-metadata endpoint on a link-local address (commonly `169.254.169.254`) that returns instance role credentials, user-data, or configuration with no additional authentication from inside the network - if the target is confirmed to run in a cloud environment, this is the highest-value destination to try. The exact path and response shape vary by provider and change over time, so don't guess blindly - request the bare metadata root first and follow what it actually returns rather than assuming a specific documented path is still current.
- **Internal service discovery**: once one internal host responds, use the same SSRF primitive to sweep a few addresses/ports in that private range - you're using the target as your scanner.
- **The target's own other services**: a request origin check, mTLS requirement, or IP allowlist on an internal admin API is often satisfied automatically because the request now legitimately comes from inside the network.

## Protocol smuggling, not just HTTP
If the vulnerable code hands the URL to a generic URL-fetching library rather than an HTTP-only client, other schemes may work and reach things HTTP can't:
- `file://` - local file read through the "fetch a URL" path, if the library resolves it
- `gopher://` - craft raw bytes to speak to a non-HTTP internal service (talk to Redis, SMTP, or similar on an internal host); effort/impact tradeoff is high, only worth it once HTTP-based SSRF against an internal target is confirmed and you specifically need to interact with a non-HTTP service
- `dict://` - another raw-protocol option some libraries support

## Bypassing naive filters
A denylist/allowlist on the hostname is routinely incomplete - try these independently, in combination, and against both the host and any redirect target:
- A URL that **redirects** to the real target after the filter approves the first hop (many SSRF filters check only the initial URL, not where a 3xx takes the request)
- **Decimal/octal/hex IP encoding** (`http://2130706433/` for `127.0.0.1`) and **IPv6** (`http://[::1]/`, `http://[::ffff:127.0.0.1]/`) forms the filter's string matching doesn't expect
- A hostname that **DNS-resolves differently at request time than at validation time** (DNS rebinding) if the filter resolves-then-checks rather than checks-the-resolved-address-at-fetch-time
- Alternate representations of "localhost" (`localtest.me`, a domain you control with an A record pointing at `127.0.0.1`, URL-encoded dots, a trailing dot on the hostname)
- Embedding credentials in the URL to confuse naive host-extraction (`http://expected-allowed-host@127.0.0.1/`)

## Confirming impact, minimally
Blind confirmation (an OOB hit) is already a real finding; escalate only as far as needed to show impact - reading one internal endpoint's banner/response, or one metadata field, is enough. Don't pivot deeper into an internal network than needed to demonstrate the boundary crossed, per the minimum-evidence-necessary principle.

## Tools
- `interactsh` for out-of-band confirmation of blind SSRF - this is the primary tool for this class, use it first
- `http` to send the exact crafted URL/payload with full control over the request, no shell-quoting issues with `gopher://`'s raw-byte payloads
- `nuclei` with `-oast` enabled (off by default in this harness) for broad SSRF-pattern scanning once you've confirmed the primitive manually
- `surface` to find candidate URL-accepting parameters across the app (webhook configs, import features, avatar/image-by-URL fields) before testing one by one

## Reporting
State the exact parameter, the payload used, and the strongest evidence obtained - an OOB callback log, a cloud-metadata field value, or a reachable internal response - and whether it was blind (OOB only) or had in-band confirmation. Note which filter bypass (if any) was needed, since that changes the fix from "add validation" to "fix the validation's TOCTOU/encoding gap."
