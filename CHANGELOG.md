# Changelog

## 0.1.2 — 2026-10-03

Documentation. No code changes.

- `/patchwork/up` is documented as a required step and included in the routes example, which previously left it out. Without that route a connection can never report verified.
- The connection check now covers what **verified**, **reachable** and **unreachable** each mean, that the path is fixed and resolved against the connection's `base_url`, that only a `minted` connection can be cryptographically verified, and that a redirect or a 404 is what usually produces *reachable* when *verified* was expected.
- Corrected the request secret rotation order. Patchwork generates that secret and starts signing with the new one as soon as it is rotated, so the rotation and the deploy go together; `previous_request_secret` covers requests already signed with the old secret.

## 0.1.1 — 2026-10-03

Packaging and documentation. No code changes.

- `documentation_uri`, `source_code_uri`, `bug_tracker_uri` and `changelog_uri` resolve. The 0.1.0 links pointed into a repository that is not public.
- README: the Patchwork endpoints are shown as named actions on one controller, with links to the platform guides.

## 0.1.0 — 2026-10-02

First release. Mint the session tokens your frontend presents to Patchwork, verify the tool calls Patchwork makes to your backend, and verify webhook deliveries.

### Added

- `Patchwork.configure` — the signing key, issuer, audience and request secrets in one place. `inspect` redacts all three secrets, so a config that reaches a log line or an error tracker doesn't carry the private key with it.
- `Patchwork::SessionToken` — mint and verify the RS256 token your frontend hands Patchwork.
- `Patchwork::Subject` — validate any subject, or declare a composite format once with `Subject.define` and let `encode`/`decode` enforce the order, the delimiter and the part count.
- `Patchwork::Signature` — the signing scheme itself, both directions, including rotation across two secrets.
- `Patchwork::Gateway` — Rack middleware that verifies the tool calls Patchwork makes to you: signature, then session token, then your own `resolve`. Works in Rails, Sinatra, Hanami or bare Rack, and only loads when Rack is present.
- `Patchwork::Rails::Presented` — the same checks as a controller concern, for when middleware is too broad. Needs `activesupport`, and loads only on `require "patchwork/rails"`.
- `Patchwork::Mint.relay` — answers Patchwork's server-to-server mint, which covers relay connections and every Playground run.
- `Patchwork::Webhook` — verifies deliveries against the webhook endpoint's own secret and parses the event.
- `Patchwork::HealthCheck` — the proof that makes **Test** on a connection report *verified* rather than merely reachable.
- `Patchwork::BridgeAssertion` — issue and verify the signed subject for an MCP login bridge.
- `Patchwork::SigningKey` — publish your JWKS. The `kid` defaults to the key's RFC 7638 thumbprint, so rotating the key rotates the `kid` with it.

### Security

Everything below was found by an adversarial audit before release, reproduced with a runnable proof of concept, and fixed with a regression test.

- Verification hashes the body once and computes one MAC per secret, accepts at most 8 `v1=` values and a 1 KB header, and parses strictly. Before this, a single unauthenticated request with a large body and many candidate signatures cost seconds of CPU.
- A malformed or stale signature header is refused **before the body is read**. Signed bodies are capped at 1 MiB (configurable) and control endpoints at 16 KB.
- A blank or whitespace-only secret raises `ConfigurationError`. An empty string is a valid HMAC key, so accepting one would make every signature forgeable.
- RS256 is pinned against your own public key. HS256 signed with that public key, `alg: none` in any casing, and the `jwk`, `jku` and `kid` headers are all refused.
- A token whose own `exp - iat` exceeds `max_token_lifetime` (900s by default) is refused even with a valid signature.
- Subject validation refuses rather than normalises, and rejects Unicode edge whitespace and control characters. Trimming a trailing space would silently merge two data partitions; CR and LF matter because relay carries the subject in a header.
- `Subject::Format#encode` requires a round trip, so a multi-character delimiter cannot make two different sets of parts produce one subject string.
- A signed request carrying `X-HTTP-Method-Override`, or one `Rack::MethodOverride` has already rewritten, is a 401.
- A truthy-but-empty `resolve` result — an empty relation, an empty string — refuses the request rather than authorising it.
- The `patchwork.*` env keys are cleared on entry on every path, so only the gateway can mark a request as Patchwork's.
- 401 bodies are generic, so they reveal neither your audience nor your issuer.
- The signing key must be an unencrypted RSA private key of at least 2048 bits, parsed with an explicit empty passphrase so an encrypted key errors instead of blocking boot on a prompt.
- The health proof is domain-separated from request signatures, so answering unsigned probes is not a signing oracle.
- The `jwt` floor is `>= 2.10.3`, excluding 3.0.0 through 3.1.2, which are affected by GHSA-c32j-vqhx-rx3x. The gem is not exploitable through that advisory, but a consumer should not resolve to a vulnerable `jwt` because of us.

### Known limitation

The signature covers the method, the path and the raw body — **not the query string** — and Patchwork sends a GET tool's arguments as query parameters. So a GET tool's arguments are not integrity-protected. Give any tool whose arguments matter a `POST` binding, where the arguments travel in the signed body. A `v2=` scheme that covers the query is planned, and will be accepted alongside `v1=` so this version keeps working.
